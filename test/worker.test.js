// test/worker.test.js — end-to-end worker.fetch() against mocked Workers
// globals (fetch, caches) and fake D1. Covers the wire paths: DoH GET/POST,
// mutations, class rejection, upstream forwarding, and answer-level rebinding.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker.js';
import { buildQuery, buildResponse, v4rdata, FakeKV } from './helpers.js';

// ---- fake Workers globals (must precede any query that triggers loads) -------

const BLOCKLIST_URL = 'https://list.test/regression/domains';
const UPSTREAM_URL = 'https://upstream.test/dns-query';

class MemCache {
  constructor() { /** @type {Map<string, Response>} */ this.map = new Map(); }
  /**
   * @param {Request|string} reqOrStr
   * @returns {Promise<Response|undefined>}
   */
  async match(reqOrStr) {
    const key = typeof reqOrStr === 'string' ? reqOrStr : reqOrStr.url;
    return this.map.get(key)?.clone();
  }
  /** @param {Request|string} req @param {Response} res */
  async put(req, res) {
    this.map.set(typeof req === 'string' ? req : req.url, res.clone());
  }
}

const REAL_FETCH = globalThis.fetch;

globalThis.caches = { default: new MemCache() };
/** @param {string|Request|URL} input @param {RequestInit} [init] */
globalThis.fetch = async (input, init) => {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  if (url === BLOCKLIST_URL) {
    return new Response('# comment\nblocklist.test\n0.0.0.0 ads.blocklist.test\n\n', { status: 200 });
  }
  if (url === UPSTREAM_URL) {
    const q = new Uint8Array(/** @type {ArrayBuffer} */ (init && init.body));
    // Echo the query with one public A record; mutated per-test below.
    return new Response(buildResponse(q, globalThis.__answers ?? [{ type: 1, rdata: v4rdata('93.184.216.34') }]));
  }
  throw new Error('unexpected fetch: ' + url);
};

after(() => { globalThis.fetch = REAL_FETCH; });

class FakeD1 {
  constructor() {
    /** @type {Array<Record<string, any>>} */
    this.rows = [];
    /** @type {Array<{sql: string, args: any[]}>} */
    this.ops = [];
    this.sn = 1;
  }
  /** @param {string} sql */
  prepare(sql) {
    const self = this;
    /** @param {any[]} args */
    const exec = (args) => {
      self.ops.push({ sql, args });
      if (/^INSERT/i.test(sql)) {
        self.rows.push({
          id: self.sn++, domain: args[0], status: args[1],
          filter: args[2], ts: args[3], qtype: args[4],
        });
      } else if (/^DELETE.*WHERE ts </i.test(sql)) {
        self.rows = self.rows.filter((r) => !(r.ts < args[0]));
      } else if (/^DELETE.*WHERE id =/i.test(sql)) {
        self.rows = self.rows.filter((r) => r.id !== args[0]);
      } else if (/^DELETE/i.test(sql)) {
        self.rows = [];
      }
      return { success: true };
    };
    return {
      run: () => exec([]),
      /** @param {any[]} a */
      bind: (...a) => ({
        run: () => exec(a),
        all: async () => ({ results: self.rows }),
        first: async () => ({ n: self.rows.length }),
      }),
      all: async () => ({ results: self.rows }),
      first: async () => ({ n: self.rows.length }),
    };
  }
}

// ---- env / request helpers -----------------------------------------------------

/**
 * @param {{RULES?: KVLike, kv?: FakeKV, d1?: FakeD1, password?: string, assets?: unknown}} [overrides]
 * @returns {Env}
 */
function mkEnv(overrides = {}) {
  return {
    RULES: overrides.RULES ?? overrides.kv ?? null,
    LOGS: /** @type {D1Like|undefined} */ (overrides.d1),
    DASHBOARD_PASSWORD: overrides.password ?? 'pw',
    BLOCKLIST_URL,
    UPSTREAM_URL,
    ASSETS: /** @type {Env['ASSETS']} */ (overrides.assets),
  };
}

/**
 * @param {Env} env
 * @param {Uint8Array} query
 * @param {{headers?: Record<string, string>}} [extra]
 * @returns {Promise<Response>}
 */
function dohGet(env, query, extra = {}) {
  const b64 = Buffer.from(query).toString('base64url');
  const url = 'https://worker.test/dns-query?dns=' + b64;
  const req = new Request(url, {
    method: 'GET',
    headers: { Accept: 'application/dns-message', ...(extra.headers || {}) },
    redirect: 'manual',
  });
  return worker.fetch(req, env);
}

/**
 * @param {Env} env
 * @param {Uint8Array} query
 * @returns {Promise<Response>}
 */
function dohPost(env, query) {
  const req = new Request('https://worker.test/dns-query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/dns-message' },
    body: query,
  });
  return worker.fetch(req, env);
}

/** @param {Uint8Array} buf */
const rcode = (buf) => buf[3] & 0x0f;
/** @param {Uint8Array} buf */
const ancount = (buf) => (buf[6] << 8) | buf[7];

// ---- tests ---------------------------------------------------------------------

// NOTE: fixtures use routable TLDs (.com/.net/.org), never .example/.test —
// those are RFC 6761/6762 special-use and the default rebindProtection would
// NXDOMAIN them at NAME level before any upstream call.
test('GET /dns-query: forwarded query returns upstream answer, logged as none', async () => {
  const d1 = new FakeD1();
  const env = mkEnv({ d1 });
  globalThis.__answers = [{ type: 1, rdata: v4rdata('93.184.216.34') }];

  const res = await dohGet(env, buildQuery('public.foo.com'));
  assert.equal(res.status, 200);
  const body = new Uint8Array(await res.arrayBuffer());
  assert.equal(body[2] & 0x80, 0x80, 'QR set');
  assert.equal(rcode(body), 0);
  assert.equal(ancount(body), 1, 'upstream record passed through');
  assert.equal(res.headers.get('content-type'), 'application/dns-message');

  assert.equal(d1.rows.length, 1);
  assert.deepEqual(
    { domain: d1.rows[0].domain, status: d1.rows[0].status, filter: d1.rows[0].filter, qtype: d1.rows[0].qtype },
    { domain: 'public.foo.com', status: 'none', filter: 'upstream', qtype: 1 },
  );
});

test('GET: custom deny rule -> NXDOMAIN + logged deny', async () => {
  const kv = new (await import('./helpers.js')).FakeKV();
  const d1 = new FakeD1();
  const env = mkEnv({ kv, d1 });
  // seed a deny rule into the blob KV
  kv.data.set('rules:data', 'deny\tbanned.foo.com');
  kv.data.set('data:version', String(Date.now()));

  const res = await dohGet(env, buildQuery('sub.banned.foo.com'));
  assert.equal(res.status, 200);
  const body = new Uint8Array(await res.arrayBuffer());
  assert.equal(rcode(body), 3, 'NXDOMAIN');
  assert.equal(ancount(body), 0);
  assert.equal(d1.rows.length, 1);
  assert.equal(d1.rows[0].status, 'deny');
  assert.equal(d1.rows[0].domain, 'sub.banned.foo.com');
});

test('GET: blocklist match -> NXDOMAIN + logged blocklist', async () => {
  const d1 = new FakeD1();
  const env = mkEnv({ d1 });
  const res = await dohGet(env, buildQuery('tracker.blocklist.test'));
  const body = new Uint8Array(await res.arrayBuffer());
  assert.equal(rcode(body), 3);
  assert.equal(d1.rows[0].status, 'blocklist');
  assert.equal(d1.rows[0].filter, 'blocklist');
});

test('answer-level rebinding: upstream private IP -> NXDOMAIN + logged rebind', async () => {
  const d1 = new FakeD1();
  const env = mkEnv({ d1 });
  globalThis.__answers = [{ type: 1, rdata: v4rdata('169.254.169.254') }]; // metadata addr

  // .org chosen deliberately: must PASS the name-level filters so the check
  // exercises the post-upstream answer inspection, not rebindNameHit().
  const res = await dohGet(env, buildQuery('vuln.rebind.org'));
  const body = new Uint8Array(await res.arrayBuffer());
  assert.equal(rcode(body), 3, 'NXDOMAIN for metadata-anchored answer');
  assert.equal(ancount(body), 0, 'private answer stripped');
  assert.equal(d1.rows.length, 1);
  assert.equal(d1.rows[0].status, 'rebind');
  assert.equal(d1.rows[0].filter, 'rebind');
  globalThis.__answers = undefined;
});

test('non-IN qclass: refused before any store access, not logged', async () => {
  const d1 = new FakeD1();
  const env = mkEnv({ d1 });
  const res = await dohGet(env, buildQuery('version.bind', { qtype: 16, qclass: 3 })); // CH
  assert.equal(res.status, 200);
  const body = new Uint8Array(await res.arrayBuffer());
  assert.equal(rcode(body), 5, 'REFUSED');
  assert.equal(d1.rows.length, 0, 'not a domain decision -> no log row');
});

test('POST /dns-query: works with binary body; bad Content-Type -> 415', async () => {
  const d1 = new FakeD1();
  const env = mkEnv({ d1 });
  globalThis.__answers = [{ type: 1, rdata: v4rdata('1.2.3.4') }];
  const res = await dohPost(env, buildQuery('post.foo.org'));
  assert.equal(res.status, 200);
  const body = new Uint8Array(await res.arrayBuffer());
  assert.equal(ancount(body), 1);

  const bad = await worker.fetch(new Request('https://worker.test/dns-query', {
    method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: 'x',
  }), env);
  assert.equal(bad.status, 415);
});

test('DoH GET validation: 406 without proper Accept, 400 without/bad dns', async () => {
  const env = mkEnv({});
  const noAccept = await worker.fetch(new Request('https://worker.test/dns-query?dns=AAAA', {
    headers: { Accept: 'application/json' },
  }), env);
  assert.equal(noAccept.status, 406);

  const noDns = await worker.fetch(new Request('https://worker.test/dns-query', {
    headers: { Accept: 'application/dns-message' },
  }), env);
  assert.equal(noDns.status, 400);

  const badB64 = await worker.fetch(new Request('https://worker.test/dns-query?dns=%25%25%25', {
    headers: { Accept: 'application/dns-message' },
  }), env);
  assert.equal(badB64.status, 400);
});

test('root: browser -> 302 /dashboard; client -> assets/404', async () => {
  const env = mkEnv({ assets: { fetch: async () => new Response('ASSET-OK') } });
  const browser = await worker.fetch(new Request('https://worker.test/', {
    headers: { Accept: 'text/html,...' },
    redirect: 'manual',
  }), env);
  assert.equal(browser.status, 302);
  assert.equal(browser.headers.get('location'), 'https://worker.test/dashboard');

  const curl = await worker.fetch(new Request('https://worker.test/', {
    headers: { Accept: 'application/json' },
  }), env);
  assert.equal(await curl.text(), 'ASSET-OK', 'non-HTML flows to assets');

  const noAssets = await worker.fetch(new Request('https://worker.test/', {
    headers: { Accept: 'application/json' },
  }), mkEnv());
  assert.equal(noAssets.status, 404, 'no ASSETS binding -> 404');
});

test('healthz: reports settings and resolved URLs', async () => {
  const env = mkEnv({});
  const res = await worker.fetch(new Request('https://worker.test/healthz'), env);
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.ok, true);
  assert.equal(j.blocklistUrl, BLOCKLIST_URL);
  assert.equal(j.upstreamUrl, UPSTREAM_URL);
  assert.equal(typeof j.settings.rebindProtection, 'boolean');
  assert.equal(j.dashboardConfigured, true);
});

test('D1 insert failure never breaks the DNS answer', async () => {
  /** @type {any} */
  const d1 = {
    prepare: () => ({
      run: async () => { throw new Error('d1 down'); },
      bind: () => ({ run: async () => { throw new Error('d1 down'); } }),
    }),
  };
  const env = mkEnv({ d1 });
  globalThis.__answers = [{ type: 1, rdata: v4rdata('5.6.7.8') }];
  const res = await dohGet(env, buildQuery('resilient.foo.net'));
  assert.equal(res.status, 200, 'answer still delivered');
  const body = new Uint8Array(await res.arrayBuffer());
  assert.equal(ancount(body), 1);
});

test('unknown API route -> 404 even without D1', async () => {
  const env = mkEnv({ d1: undefined });
  const cookie = 'dns_dash_session=pw';
  const res = await worker.fetch(new Request('https://worker.test/api/none', {
    headers: { Cookie: cookie },
  }), env);
  assert.equal(res.status, 404);
});

test('upstream failure -> 502 with REFUSED payload', async () => {
  const env = mkEnv({});
  const savedFetch = globalThis.fetch;
  /** @param {string|Request|URL} input @returns {Promise<Response>} */
  globalThis.fetch = async (input) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (url === BLOCKLIST_URL) return new Response('ok.test\n');
    throw new Error('upstream unreachable');
  };
  try {
    const res = await dohGet(env, buildQuery('ok.somehost.net'));
    assert.equal(res.status, 502);
    const body = new Uint8Array(await res.arrayBuffer());
    assert.equal(rcode(body), 5, 'REFUSED wire code');
  } finally {
    globalThis.fetch = savedFetch;
  }
});
test('logPassed=false: passed queries unlogged, blocked still logged', async () => {
  const d1 = new FakeD1();
  const env = mkEnv({ d1, kv: new FakeKV() });

  const login = await worker.fetch(new Request('https://worker.test/api/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'pw' }),
  }), env);
  const sc = login.headers.get('set-cookie');
  assert.ok(sc, 'session cookie expected');
  const cookie = sc.split(';')[0];

  const off = await worker.fetch(new Request('https://worker.test/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookie },
    body: JSON.stringify({ logPassed: false }),
  }), env);
  assert.equal(off.status, 200);

  globalThis.__answers = [{ type: 1, rdata: v4rdata('5.6.7.8') }];
  const passed = await dohGet(env, buildQuery('passed.example.net'));
  assert.equal(passed.status, 200, 'answer still delivered when unlogged');

  const blocked = await dohGet(env, buildQuery('ads.blocklist.test'));
  assert.equal(blocked.status, 200);

  const inserts = d1.ops.filter((o) => /^INSERT/i.test(o.sql));
  assert.equal(inserts.length, 1, 'only the block was logged');
  assert.equal(d1.rows[0].domain, 'ads.blocklist.test');
  assert.equal(d1.rows[0].status, 'blocklist');
});
