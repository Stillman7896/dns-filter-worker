// test/api.test.js — /api routes: session auth, rules, settings, filter lists.
// Uses real Request/Response (Node >= 18) against handleApi with FakeKV stores.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleApi } from '../dashboard.js';
import { RuleStore } from '../rules.js';
import { RouteStore } from '../routing.js';
import { TextSetStore, normalizeKeyword, normalizeRegex } from '../lists.js';
import { SettingsStore } from '../settings.js';
import { Blocklist, DEFAULT_BLOCKLIST_URL, MAX_BLOCKLIST_URLS } from '../blocklist.js';
import { buildQuery, buildResponse, FakeKV, v4rdata } from './helpers.js';

/**
 * @param {KVLike} kv
 * @returns {ApiCtx}
 */
function mkCtx(kv) {
  return {
    rules: new RuleStore(kv),
    settings: new SettingsStore(kv),
    routes: new RouteStore(kv),
    keywords: new TextSetStore(kv, 'keywords:data', normalizeKeyword),
    tlds: new TextSetStore(kv, 'tlds:data'),
    regex: new TextSetStore(kv, 'regex:data', normalizeRegex),
    testFn: async (domain, env) => ({ domain, status: 'none', filter: 'upstream', matched: null }),
  };
}

const PASSWORD = 'hunter2';

/**
 * @param {ApiCtx} ctx
 * @param {Env} env
 * @param {string} path
 * @param {{method?: string, body?: unknown, cookie?: string}} [opts]
 * @returns {Promise<Response>}
 */
function call(ctx, env, path, { method = 'GET', body, cookie } = {}) {
  /** @type {Record<string, string>} */
  const headers = { 'Content-Type': 'application/json' };
  if (cookie) headers.Cookie = cookie;
  const req = new Request('https://worker.test' + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return handleApi(req, env, new URL(req.url), ctx);
}

/** @param {Response} res @returns {string} */
function cookieFrom(res) {
  const sc = res.headers.get('set-cookie');
  assert.ok(sc, 'session cookie set');
  return sc.split(';')[0];
}

// ---- session ------------------------------------------------------------------

test('session: unconfigured password -> 503 everywhere', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = {};
  const login = await call(ctx, env, '/api/session', { method: 'POST', body: { password: 'x' } });
  assert.equal(login.status, 503);
  const rules = await call(ctx, env, '/api/rules');
  assert.equal(rules.status, 503);
  assert.equal((await rules.json()).code, 'unconfigured');
});

test('session: wrong password 401, right password sets cookie', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };

  const bad = await call(ctx, env, '/api/session', { method: 'POST', body: { password: 'nope' } });
  assert.equal(bad.status, 401);

  const ok = await call(ctx, env, '/api/session', { method: 'POST', body: { password: PASSWORD } });
  assert.equal(ok.status, 200);

  const bearer = await call(ctx, env, '/api/session', {
    method: 'POST',
    // no JSON body — bearer path
  });
  assert.equal(bearer.status, 401, 'no auth header and no body -> 401');
});

test('auth: cookie grants access, missing cookie -> 401 without WWW-Authenticate', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const login = await call(ctx, env, '/api/session', { method: 'POST', body: { password: PASSWORD } });
  const cookie = cookieFrom(login);

  const ok = await call(ctx, env, '/api/rules', { cookie });
  assert.equal(ok.status, 200);

  const anon = await call(ctx, env, '/api/rules');
  assert.equal(anon.status, 401);
  assert.equal(anon.headers.get('www-authenticate'), null,
    'must NOT send WWW-Authenticate (no browser dialog)');

  const wrongCookie = await call(ctx, env, '/api/rules', { cookie: 'dns_dash_session=wrong' });
  assert.equal(wrongCookie.status, 401);
});

// ---- rules --------------------------------------------------------------------

test('rules: add/get/delete with validation', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const login = await call(ctx, env, '/api/session', { method: 'POST', body: { password: PASSWORD } });
  const cookie = cookieFrom(login);

  const added = await call(ctx, env, '/api/rules', {
    method: 'POST', cookie, body: { domain: 'Evil.Example.COM', kind: 'deny' },
  });
  assert.equal(added.status, 200);
  assert.equal((await added.json()).domain, 'evil.example.com', 'normalized');

  const badDomain = await call(ctx, env, '/api/rules', {
    method: 'POST', cookie, body: { domain: 'nodots', kind: 'deny' },
  });
  assert.equal(badDomain.status, 400);

  const badKind = await call(ctx, env, '/api/rules', {
    method: 'POST', cookie, body: { domain: 'ok.com', kind: 'maybe' },
  });
  assert.equal(badKind.status, 400);

  const listed = await call(ctx, env, '/api/rules', { cookie });
  assert.deepEqual((await listed.json()).rules, [{ domain: 'evil.example.com', kind: 'deny', src: 'custom' }]);

  const del = await call(ctx, env, '/api/rules?domain=evil.example.com', { method: 'DELETE', cookie });
  assert.equal((await del.json()).existed, true);

  const listed2 = await call(ctx, env, '/api/rules', { cookie });
  assert.deepEqual((await listed2.json()).rules, []);
});

test('rules: blocklist @@ exceptions surface as read-only allow rows', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const bl = new Blocklist();
  bl.load(['||tracker.test^', '@@sub.tracker.test', '@@plain.blocklist.test'].join('\n'));
  ctx.blocklist = bl;
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));

  await call(ctx, env, '/api/rules', {
    method: 'POST', cookie, body: { domain: 'custom.test', kind: 'deny' },
  });

  const listed = await call(ctx, env, '/api/rules', { cookie });
  assert.deepEqual((await listed.json()).rules, [
    { domain: 'custom.test', kind: 'deny', src: 'custom' },
    { domain: 'plain.blocklist.test', kind: 'allow', src: 'blocklist' },
    { domain: 'sub.tracker.test', kind: 'allow', src: 'blocklist' },
  ], 'custom rows first, blocklist rows sorted after');

  const del = await call(ctx, env, '/api/rules?domain=sub.tracker.test', { method: 'DELETE', cookie });
  assert.equal(del.status, 400, 'blocklist-sourced rows are read-only');
  assert.match((await del.json()).error, /blocklist/);
  assert.equal((await (await call(ctx, env, '/api/rules', { cookie })).json()).rules.length, 3, 'row unchanged');

  const delCustom = await call(ctx, env, '/api/rules?domain=custom.test', { method: 'DELETE', cookie });
  assert.equal(delCustom.status, 200, 'custom rows still deletable');
});

test('rules: bulk import reports applied and skipped', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));

  const res = await call(ctx, env, '/api/rules/bulk', {
    method: 'POST', cookie,
    body: { kind: 'deny', domains: 'a.com\nb.com\n\nnot valid!!' },
  });
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.added, 2);
  assert.deepEqual(j.skipped, ['not valid!!']);
});

test('rules: unknown route -> 404 (not swallowed by logs guard)', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));
  const res = await call(ctx, env, '/api/nope', { cookie });
  assert.equal(res.status, 404);
});

// ---- test endpoint -------------------------------------------------------------

test('test endpoint: delegates to injected pipeline', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));
  const res = await call(ctx, env, '/api/test?domain=example.com', { cookie });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), {
    domain: 'example.com', status: 'none', filter: 'upstream', matched: null,
    unicode: null,
  });

  const bad = await call(ctx, env, '/api/test?domain=nodots', { cookie });
  assert.equal(bad.status, 400);
});

test('test endpoint: internationalized input probes the A-label and reports both spellings', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));

  const res = await call(ctx, env, `/api/test?domain=${encodeURIComponent('bücher.de')}`, { cookie });
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.domain, 'xn--bcher-kva.de', 'pipeline only ever sees the A-label');
  assert.equal(j.unicode, 'bücher.de', 'translation rides along with the verdict');

  const wire = await call(ctx, env, '/api/test?domain=xn--bcher-kva.de', { cookie });
  assert.equal((await wire.json()).unicode, 'bücher.de', 'punycode input is translated too');

  const noDot = await call(ctx, env, `/api/test?domain=${encodeURIComponent('вася')}`, { cookie });
  assert.equal(noDot.status, 400, 'still validated as a domain');
});

// ---- settings -----------------------------------------------------------------

test('settings: upstream provider + presets travel with the settings payload', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));

  const body = await (await call(ctx, env, '/api/settings', { cookie })).json();
  assert.equal(body.settings.upstreamPreset, '');
  assert.equal(body.settings.upstreamUrl, '');
  assert.equal(body.settings.upstreamRelay, '');
  assert.equal(body.upstream.id, 'quad9', 'default provider when nothing is chosen');
  assert.ok(Array.isArray(body.upstreamPresets));
  assert.ok(body.upstreamPresets.some((/** @type {{id: string}} */ p) => p.id === 'cloudflare-odoh'));

  const saved = await call(ctx, env, '/api/settings', {
    method: 'POST', cookie, body: { upstreamPreset: 'google' },
  });
  assert.equal(saved.status, 200);
  const j = await saved.json();
  assert.equal(j.settings.upstreamPreset, 'google');
  assert.equal(j.upstream.url, 'https://dns.google/dns-query');
});

test('settings: an unusable provider combination is refused, not saved', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));

  const unknown = await call(ctx, env, '/api/settings', {
    method: 'POST', cookie, body: { upstreamPreset: 'mystery' },
  });
  assert.equal(unknown.status, 400);
  assert.match((await unknown.json()).error, /unknown upstream provider/);

  const custom = await call(ctx, env, '/api/settings', {
    method: 'POST', cookie, body: { upstreamPreset: 'custom' },
  });
  assert.equal(custom.status, 400);
  assert.match((await custom.json()).error, /https:\/\/ DoH URL/);

  const odoh = await call(ctx, env, '/api/settings', {
    method: 'POST', cookie, body: { upstreamPreset: 'cloudflare-odoh' },
  });
  assert.equal(odoh.status, 400);
  assert.match((await odoh.json()).error, /relay URL/);

  // Nothing above changed the stored provider.
  const current = await (await call(ctx, env, '/api/settings', { cookie })).json();
  assert.equal(current.settings.upstreamPreset, '');

  const customOk = await call(ctx, env, '/api/settings', {
    method: 'POST', cookie, body: { upstreamPreset: 'custom', upstreamUrl: 'https://doh.internal/dns-query' },
  });
  assert.equal(customOk.status, 200);
  assert.equal((await customOk.json()).upstream.url, 'https://doh.internal/dns-query');
});

test('settings: GET defaults, POST patch incl. retention validation', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));

  const get = await call(ctx, env, '/api/settings', { cookie });
  const s0 = (await get.json()).settings;
  assert.equal(s0.rebindProtection, true);
  assert.equal(s0.idnBlock, false);
  assert.equal(s0.logPassed, true);
  assert.equal(s0.logRetentionDays, 30);

  const post = await call(ctx, env, '/api/settings', {
    method: 'POST', cookie, body: { idnBlock: true, logRetentionDays: 7, logPassed: false },
  });
  const s1 = (await post.json()).settings;
  assert.equal(s1.idnBlock, true);
  assert.equal(s1.logPassed, false);
  assert.equal(s1.logRetentionDays, 7);

  const clamped = await call(ctx, env, '/api/settings', {
    method: 'POST', cookie, body: { logRetentionDays: 99999 },
  });
  assert.equal((await clamped.json()).settings.logRetentionDays, 3650);

  const badType = await call(ctx, env, '/api/settings', {
    method: 'POST', cookie, body: { logRetentionDays: 'soon' },
  });
  assert.equal(badType.status, 400);

  const noValid = await call(ctx, env, '/api/settings', {
    method: 'POST', cookie, body: { flurb: 1 },
  });
  assert.equal(noValid.status, 400);
});

// ---- filter lists --------------------------------------------------------------

test('filters: tlds + keywords CRUD with validation', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));

  const add = await call(ctx, env, '/api/filters/tlds', {
    method: 'POST', cookie, body: { value: '.ZIP' },
  });
  assert.equal(add.status, 200);
  assert.deepEqual((await add.json()).items, ['zip']);

  const dup = await call(ctx, env, '/api/filters/tlds', {
    method: 'POST', cookie, body: { value: 'zip' },
  });
  assert.equal((await dup.json()).added, false);

  const invalid = await call(ctx, env, '/api/filters/tlds', {
    method: 'POST', cookie, body: { value: 'co.uk' },
  });
  assert.equal(invalid.status, 400);

  const kwBad = await call(ctx, env, '/api/filters/keywords', {
    method: 'POST', cookie, body: { value: 'DoubleClick' },
  });
  assert.equal(kwBad.status, 400, 'uppercase can never match; rejected, not rewritten');

  const kw = await call(ctx, env, '/api/filters/keywords', {
    method: 'POST', cookie, body: { value: 'doubleclick' },
  });
  assert.deepEqual((await kw.json()).items, ['doubleclick']);

  const leadingDash = await call(ctx, env, '/api/filters/keywords', {
    method: 'POST', cookie, body: { value: '-ads' },
  });
  assert.deepEqual((await leadingDash.json()).items, ['-ads', 'doubleclick'], 'stored verbatim');

  const rm = await call(ctx, env, '/api/filters/tlds?value=zip', { method: 'DELETE', cookie });
  assert.equal((await rm.json()).removed, true);
  assert.deepEqual((await (await call(ctx, env, '/api/filters/tlds', { cookie })).json()).items, []);
});

test('filters: regex CRUD with validation (compile + bounds)', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));

  const add = await call(ctx, env, '/api/filters/regex', {
    method: 'POST', cookie, body: { value: '^ads\\.' },
  });
  assert.equal(add.status, 200);
  assert.deepEqual((await add.json()).items, ['^ads\\.']);

  const dup = await call(ctx, env, '/api/filters/regex', {
    method: 'POST', cookie, body: { value: '^ads\\.' },
  });
  assert.equal((await dup.json()).added, false);

  const broken = await call(ctx, env, '/api/filters/regex', {
    method: 'POST', cookie, body: { value: '(unclosed' },
  });
  assert.equal(broken.status, 400, 'patterns that do not compile are rejected at the API');

  const tooShort = await call(ctx, env, '/api/filters/regex', {
    method: 'POST', cookie, body: { value: 'ab' },
  });
  assert.equal(tooShort.status, 400);

  const spaced = await call(ctx, env, '/api/filters/regex', {
    method: 'POST', cookie, body: { value: '^a b$' },
  });
  assert.equal(spaced.status, 400, 'no whitespace in patterns');

  const rm = await call(ctx, env, '/api/filters/regex?value=' + encodeURIComponent('^ads\\.'), {
    method: 'DELETE', cookie,
  });
  assert.equal((await rm.json()).removed, true);
  assert.deepEqual((await (await call(ctx, env, '/api/filters/regex', { cookie })).json()).items, []);
});

test('filters: GET loads stored lists from KV on a cold isolate', async () => {
  // A fresh isolate has an empty in-memory set; only the DNS hot path and
  // writes used to refresh the stores, so the dashboard listed nothing.
  const kv = new FakeKV({
    'keywords:data': 'doubleclick\ntelemetry',
    'tlds:data': 'zip',
    'data:version': '42',
  });
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));

  const kw = await (await call(ctx, env, '/api/filters/keywords', { cookie })).json();
  assert.deepEqual(kw.items, ['doubleclick', 'telemetry']);

  const tlds = await (await call(ctx, env, '/api/filters/tlds', { cookie })).json();
  assert.deepEqual(tlds.items, ['zip']);
});

// ---- logs without D1 ------------------------------------------------------------

test('logs: missing D1 binding -> 501 (not 503, not 404)', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));
  const res = await call(ctx, env, '/api/logs', { cookie });
  assert.equal(res.status, 501);
  assert.equal((await res.json()).code, 'no_d1');
});

// ---- logs stats (D1) -----------------------------------------------------------

// Minimal D1 for the stats endpoint: each prepare() sniffed and bound to a
// canned handler that matches the real GROUP BY queries in dashboard.js.
/** @returns {D1Like} */
function statsD1() {
  const statusRows = [
    { status: 'blocklist', n: 5 }, { status: 'none', n: 3 },
    { status: 'allow', n: 1 }, { status: 'rebind', n: 2 },
  ];
  const topBlocked = [
    { domain: 'ads.example', n: 3 }, { domain: 'tracker.io', n: 2 },
  ];
  const topClients = [
    { client: 'phone', n: 4 }, { client: 'laptop', n: 2 },
  ];
  const hourRows = [{ hour: 10, n: 4 }, { hour: 11, n: 6 }];
  const totalRow = { n: 11 };
  /** @param {string} sql @returns {any} */
  const handlerFor = (sql) => {
    if (/GROUP BY status/i.test(sql)) return statusRows;
    if (/WHERE status IN/i.test(sql)) return topBlocked;
    if (/GROUP BY client/i.test(sql)) return topClients;
    if (/GROUP BY hour/i.test(sql)) return hourRows;
    if (/^SELECT COUNT\(\*\) AS n FROM dns_logs$/i.test(sql.trim())) return totalRow;
    throw new Error('unexpected STATS sql: ' + sql);
  };
  /** @param {any} rows @returns {{all: () => Promise<{results: any}>, first: () => Promise<any>, run: () => Promise<{success: boolean}>}} */
  const binding = (rows) => ({
    all: async () => ({ results: rows }),
    first: async () => (Array.isArray(rows) ? rows[0] : rows),
    run: async () => ({ success: true }),
  });
  return {
    prepare(sql) {
      return {
        bind: () => binding(handlerFor(sql)),
        all: async () => ({ results: handlerFor(sql) }),
        first: async () => handlerFor(sql),
        run: async () => ({ success: true }),
      };
    },
  };
}

test('logs/stats: aggregates status mix, top blocked, hourly buckets', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD, LOGS: statsD1() };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));
  const res = await call(ctx, env, '/api/logs/stats', { cookie });
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.total, 11);
  assert.equal(j.byStatus.total, 11);
  assert.equal(j.byStatus.rows.length, 4);
  assert.equal(j.topBlocked[0].domain, 'ads.example');
  assert.deepEqual(j.topClients[0], { client: 'phone', n: 4 });
  assert.ok(Array.isArray(j.last24h) && j.last24h.length === 24);
  assert.equal(j.last24h[10], 4);
  assert.equal(j.last24h[11], 6);
  assert.equal(j.last24h[0], 0);
});

test('logs/stats: requires D1 (501 when missing)', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));
  const res = await call(ctx, env, '/api/logs/stats', { cookie });
  assert.equal(res.status, 501);
});

// ---- logs list: client / untagged filters (D1) ----------------------------------

// In-memory D1 for /api/logs: WHERE args are really applied, so the client
// and untagged filters are verified end to end instead of just sniffed.
const LOG_ROWS = [
  { id: 1, domain: 'a.example', status: 'none', filter: 'upstream', ts: 5000, qtype: 1, client: 'laptop' },
  { id: 2, domain: 'ads.example', status: 'deny', filter: 'denylist', ts: 4000, qtype: 1, client: 'phone' },
  { id: 3, domain: 'b.example', status: 'none', filter: 'upstream', ts: 3000, qtype: 28, client: null },
  { id: 4, domain: 'c.example', status: 'tld', filter: 'tld', ts: 2000, qtype: 1, client: 'laptop' },
];

/** @returns {D1Like & {rows: Array<Record<string, any>>}} */
function logsD1() {
  const rows = LOG_ROWS.slice();
  /** @param {string} sql @param {any[]} args @returns {[any[], number]} filtered rows + how many args the WHERE consumed */
  const conds = (sql, args) => {
    const m = /WHERE ([^]*?)(?=\s+ORDER BY|\s+GROUP BY|\s+LIMIT|$)/i.exec(sql);
    if (!m) return [rows, 0];
    let i = 0;
    let out = rows;
    for (const raw of m[1].split(/\s+AND\s+/i)) {
      const part = raw.trim();
      if (/^domain LIKE \?/i.test(part)) {
        const needle = String(args[i++]).replaceAll('%', '');
        out = out.filter((r) => r.domain.includes(needle));
      } else if (/^status = \?/i.test(part)) {
        const v = String(args[i++]);
        out = out.filter((r) => r.status === v);
      } else if (/^client = \?/i.test(part)) {
        const v = String(args[i++]);
        out = out.filter((r) => r.client === v);
      } else if (/^client IS NOT NULL/i.test(part)) {
        out = out.filter((r) => r.client !== null && r.client !== undefined);
      } else if (/^client IS NULL/i.test(part)) {
        out = out.filter((r) => r.client === null || r.client === undefined);
      } else if (/^status IN \(/i.test(part)) {
        const allowed = [...part.matchAll(/'([^']+)'/g)].map((x) => x[1]);
        out = out.filter((r) => allowed.includes(r.status));
      } else if (/^ts >= \?/i.test(part)) {
        const cutoff = Number(args[i++]);
        out = out.filter((r) => r.ts >= cutoff);
      } else {
        throw new Error('unsupported cond: ' + part);
      }
    }
    return [out, i];
  };
  /** @param {string} sql @param {any[]} args */
  const stmt = (sql, args) => {
    const [out, used] = conds(sql, args);
    const limit = Number(args[used] ?? Infinity);
    const offset = Number(args[used + 1] ?? 0);
    let results = [];
    let n = null;
    if (/^SELECT COUNT\(\*\)/i.test(sql)) n = out.length;
    else if (/GROUP BY status/i.test(sql)) {
      const tally = new Map();
      for (const r of out) tally.set(r.status, (tally.get(r.status) || 0) + 1);
      results = [...tally].map(([status, c]) => ({ status, n: c }));
    } else if (/GROUP BY domain/i.test(sql)) {
      const tally = new Map();
      for (const r of out) tally.set(r.domain, (tally.get(r.domain) || 0) + 1);
      results = [...tally].map(([domain, c]) => ({ domain, n: c })).sort((a, b) => b.n - a.n);
    } else if (/GROUP BY client/i.test(sql)) {
      const tally = new Map();
      for (const r of out) tally.set(r.client, (tally.get(r.client) || 0) + 1);
      results = [...tally].map(([client, c]) => ({ client, n: c })).sort((a, b) => b.n - a.n);
    } else if (/GROUP BY hour/i.test(sql)) {
      const tally = new Map();
      for (const r of out) {
        const hour = Math.floor(r.ts / 3600000) % 24;
        tally.set(hour, (tally.get(hour) || 0) + 1);
      }
      results = [...tally].map(([hour, c]) => ({ hour, n: c }));
    } else if (/ORDER BY ts DESC/i.test(sql)) {
      results = out.slice().sort((a, b) => b.ts - a.ts).slice(offset, offset + limit);
    } else if (/^DELETE FROM dns_logs/i.test(sql)) {
      for (let k = rows.length - 1; k >= 0; k--) if (out.includes(rows[k])) rows.splice(k, 1);
    } else {
      throw new Error('unexpected LOGS sql: ' + sql);
    }
    return {
      all: async () => ({ results }),
      first: async () => (n === null ? results[0] : { n }),
      run: async () => ({ success: true }),
    };
  };
  return {
    rows,
    prepare(sql) {
      return {
        bind: (...a) => stmt(sql, a),
        all: () => stmt(sql, []).all(),
        first: () => stmt(sql, []).first(),
        run: () => stmt(sql, []).run(),
      };
    },
  };
}

test('logs: client tag and untagged filters, rows carry the client', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD, LOGS: logsD1() };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));

  const laptop = await (await call(ctx, env, '/api/logs?client=laptop', { cookie })).json();
  assert.equal(laptop.total, 2);
  assert.deepEqual(laptop.logs.map((/** @type {{id: number}} */ r) => r.id), [1, 4], 'newest first');
  assert.equal(laptop.logs[0].client, 'laptop', 'rows carry the client tag');

  const untagged = await (await call(ctx, env, '/api/logs?untagged=1', { cookie })).json();
  assert.equal(untagged.total, 1);
  assert.equal(untagged.logs[0].id, 3);
  assert.equal(untagged.logs[0].client, null);

  const combined = await (await call(ctx, env, '/api/logs?search=example&client=phone', { cookie })).json();
  assert.equal(combined.total, 1, 'client stacks with the domain search');
  assert.equal(combined.logs[0].id, 2);
});

test('logs: delete filtered honours the client filter; stats tally clients', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const db = logsD1();
  const env = { DASHBOARD_PASSWORD: PASSWORD, LOGS: db };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));

  const bare = await call(ctx, env, '/api/logs', { method: 'DELETE', cookie });
  assert.equal(bare.status, 400, 'still needs ?clear=1 or a filter');

  const untaggedDel = await call(ctx, env, '/api/logs?untagged=1', { method: 'DELETE', cookie });
  assert.equal(untaggedDel.status, 200, 'untagged=1 counts as a filter on its own');
  assert.deepEqual(db.rows.map((r) => r.id), [1, 2, 4]);

  const byClient = await call(ctx, env, '/api/logs?client=phone', { method: 'DELETE', cookie });
  assert.equal(byClient.status, 200);
  assert.deepEqual(db.rows.map((r) => r.id), [1, 4], 'only the tagged rows are gone');

  const stats = await (await call(ctx, env, '/api/logs/stats', { cookie })).json();
  assert.deepEqual(stats.topClients, [{ client: 'laptop', n: 2 }], 'untagged rows never appear in the tally');
});

// ---- config backup: export / import --------------------------------------------

/** @param {KVLike} kv */
async function login(kv) {
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));
  return { ctx, env, cookie };
}

test('backup: export returns full config snapshot', async () => {
  const kv = new FakeKV();
  const { ctx, env, cookie } = await login(kv);
  await call(ctx, env, '/api/rules', { method: 'POST', cookie, body: { domain: 'old.com', kind: 'deny' } });
  await call(ctx, env, '/api/filters/tlds', { method: 'POST', cookie, body: { value: '.ZIP' } });
  await ctx.keywords.add('doubleclick');
  await ctx.regex.add('^telemetry\\.');
  await call(ctx, env, '/api/settings', { method: 'POST', cookie, body: { idnBlock: true } });

  const res = await call(ctx, env, '/api/export', { cookie });
  assert.equal(res.status, 200);
  const payload = await res.json();
  assert.equal(payload.version, 1);
  assert.ok(payload.exportedAt);
  assert.equal(payload.settings.idnBlock, true);
  assert.deepEqual(payload.rules, [{ domain: 'old.com', kind: 'deny' }]);
  assert.deepEqual(payload.tlds, ['zip']);
  assert.ok(payload.keywords.includes('doubleclick'));
  assert.deepEqual(payload.regex, ['^telemetry\\.'], 'regex list is part of the snapshot');
});

test('backup: import merge adds without clobbering existing state', async () => {
  const kv = new FakeKV();
  const { ctx, env, cookie } = await login(kv);
  await call(ctx, env, '/api/rules', { method: 'POST', cookie, body: { domain: 'old.com', kind: 'deny' } });
  await call(ctx, env, '/api/filters/tlds', { method: 'POST', cookie, body: { value: '.ZIP' } });
  await call(ctx, env, '/api/settings', { method: 'POST', cookie, body: { idnBlock: true } });
  await ctx.keywords.add('tracker');
  const exp = await (await call(ctx, env, '/api/export', { cookie })).json();

  const kv2 = new FakeKV();
  const { ctx: c2, env: e2, cookie: k2 } = await login(kv2);
  await call(c2, e2, '/api/rules', { method: 'POST', cookie: k2, body: { domain: 'fresh.net', kind: 'allow' } });

  const imp = await call(c2, e2, '/api/import', {
    method: 'POST', cookie: k2,
    body: {
      mode: 'merge',
      settings: exp.settings,
      rules: exp.rules,
      keywords: exp.keywords,
      tlds: exp.tlds,
    },
  });
  assert.equal(imp.status, 200);
  const j = await imp.json();
  assert.equal(j.mode, 'merge');
  assert.deepEqual(j.rules, { applied: 1, skipped: 0 });
  assert.deepEqual(j.tlds, { applied: 1, skipped: 0 });
  assert.ok(j.keywords.applied >= 1);
  assert.equal(j.settings, true);

  const rules = (await (await call(c2, e2, '/api/rules', { cookie: k2 })).json()).rules;
  assert.equal(rules.length, 2, 'merge keeps fresh.net');
  const s = (await (await call(c2, e2, '/api/settings', { cookie: k2 })).json()).settings;
  assert.equal(s.idnBlock, true, 'settings applied');
});

test('backup: import replace clears each section before writing', async () => {
  const kv = new FakeKV();
  const { ctx, env, cookie } = await login(kv);
  await call(ctx, env, '/api/rules', { method: 'POST', cookie, body: { domain: 'stale.com', kind: 'deny' } });
  await call(ctx, env, '/api/filters/tlds', { method: 'POST', cookie, body: { value: 'zip' } });

  const imp = await call(ctx, env, '/api/import', {
    method: 'POST', cookie,
    body: { mode: 'replace', rules: [{ domain: 'a.com', kind: 'allow' }], tlds: ['io'], keywords: [] },
  });
  assert.equal(imp.status, 200);
  const j = await imp.json();
  assert.equal(j.rules.applied, 1);
  assert.deepEqual(j.tlds, { applied: 1, skipped: 0 });
  assert.deepEqual(j.keywords, { applied: 0, skipped: 0 }, 'empty keywords clears the list');

  const rules = (await (await call(ctx, env, '/api/rules', { cookie })).json()).rules;
  assert.deepEqual(rules, [{ domain: 'a.com', kind: 'allow', src: 'custom' }]);
  const tlds = (await (await call(ctx, env, '/api/filters/tlds', { cookie })).json()).items;
  assert.deepEqual(tlds, ['io']);
});

test('backup: import validation — bad json shape, invalid entries, empty payload', async () => {
  const kv = new FakeKV();
  const { ctx, env, cookie } = await login(kv);

  const empty = await call(ctx, env, '/api/import', { method: 'POST', cookie, body: { mode: 'merge' } });
  assert.equal(empty.status, 400);

  const imp = await call(ctx, env, '/api/import', {
    method: 'POST', cookie,
    body: { rules: [{ domain: 'ok.com', kind: 'deny' }, 'garbage', { kind: 'deny' }, { domain: 'x.io', kind: 'maybe' }] },
  });
  assert.equal(imp.status, 200);
  const j = await imp.json();
  assert.deepEqual(j.rules, { applied: 1, skipped: 3 });

  const badSettings = await call(ctx, env, '/api/import', {
    method: 'POST', cookie, body: { settings: { logRetentionDays: 'nope' } },
  });
  assert.equal(badSettings.status, 400);
});

test('session: DELETE clears the dashboard cookie', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };

  const login = await call(ctx, env, '/api/session', { method: 'POST', body: { password: PASSWORD } });
  const cookie = cookieFrom(login);
  const rules = await call(ctx, env, '/api/rules', { cookie });
  assert.equal(rules.status, 200);

  const out = await call(ctx, env, '/api/session', { method: 'DELETE', cookie });
  assert.equal(out.status, 200);
  const sc = out.headers.get('set-cookie') || '';
  assert.match(sc, /dns_dash_session=;/);
  assert.match(sc, /Max-Age=0/);
});

// ---- response routes -----------------------------------------------------------

test('routes: add / list / delete with validation', async () => {
  const kv = new FakeKV();
  const { ctx, env, cookie } = await login(kv);

  const added = await call(ctx, env, '/api/routes', {
    method: 'POST', cookie, body: { domain: 'Printer.Home.LAN', value: '192.168.1.9', ttl: 60 },
  });
  assert.equal(added.status, 200);
  assert.deepEqual((await added.json()).route, {
    domain: 'printer.home.lan', type: 'a', value: '192.168.1.9', ttl: 60,
  });

  const cname = await call(ctx, env, '/api/routes', {
    method: 'POST', cookie, body: { domain: 'media.example.com', value: 'nas.home.lan' },
  });
  assert.equal((await cname.json()).route.type, 'cname');

  const listed = await call(ctx, env, '/api/routes', { cookie });
  assert.deepEqual((await listed.json()).routes.map((/** @type {RouteRule} */ r) => r.domain), ['media.example.com', 'printer.home.lan']);

  const badDomain = await call(ctx, env, '/api/routes', {
    method: 'POST', cookie, body: { domain: 'nodots', value: '192.168.1.9' },
  });
  assert.equal(badDomain.status, 400);

  const badValue = await call(ctx, env, '/api/routes', {
    method: 'POST', cookie, body: { domain: 'x.example.com', value: '999.1.1.1' },
  });
  assert.equal(badValue.status, 400);
  assert.match((await badValue.json()).error, /invalid route/);

  const del = await call(ctx, env, '/api/routes?domain=printer.home.lan', { method: 'DELETE', cookie });
  assert.equal((await del.json()).existed, true);

  const again = await call(ctx, env, '/api/routes?domain=printer.home.lan', { method: 'DELETE', cookie });
  assert.equal((await again.json()).existed, false);

  const left = await (await call(ctx, env, '/api/routes', { cookie })).json();
  assert.deepEqual(left.routes.map((/** @type {RouteRule} */ r) => r.domain), ['media.example.com']);
});

test('routes: export + import round-trip (merge keeps, replace clears)', async () => {
  const kv = new FakeKV();
  const { ctx, env, cookie } = await login(kv);
  await call(ctx, env, '/api/routes', {
    method: 'POST', cookie, body: { domain: 'nas.home.lan', value: '192.168.1.20' },
  });

  const exported = await (await call(ctx, env, '/api/export', { cookie })).json();
  assert.deepEqual(exported.routes, [
    { domain: 'nas.home.lan', type: 'a', value: '192.168.1.20', ttl: 300 },
  ]);

  const merged = await call(ctx, env, '/api/import', {
    method: 'POST', cookie,
    body: { mode: 'merge', routes: [...exported.routes, { domain: 'tv.home.lan', value: '2001:db8::5' }] },
  });
  assert.equal(merged.status, 200);
  assert.deepEqual((await merged.json()).routes, { applied: 2, skipped: 0 });

  const replaced = await call(ctx, env, '/api/import', {
    method: 'POST', cookie,
    body: { mode: 'replace', routes: [{ domain: 'only.example.com', value: '203.0.113.5' }, { bogus: 1 }] },
  });
  assert.deepEqual((await replaced.json()).routes, { applied: 1, skipped: 1 });

  const left = await (await call(ctx, env, '/api/routes', { cookie })).json();
  assert.deepEqual(left.routes.map((/** @type {RouteRule} */ r) => r.domain), ['only.example.com']);
});

// ---- upstream connection test --------------------------------------------------

test('upstream test: unknown provider and bad custom URL are rejected with 400', async () => {
  const kv = new FakeKV();
  const { ctx, env, cookie } = await login(kv);

  const unknown = await call(ctx, env, '/api/upstream/test', {
    method: 'POST', cookie, body: { preset: 'mystery' },
  });
  assert.equal(unknown.status, 400);

  const noUrl = await call(ctx, env, '/api/upstream/test', {
    method: 'POST', cookie, body: { preset: 'custom' },
  });
  assert.equal(noUrl.status, 400);

  const noUrl2 = await call(ctx, env, '/api/upstream/test', {
    method: 'POST', cookie, body: { url: 'http://dns.example' },
  });
  assert.equal(noUrl2.status, 400);
});

test('upstream test: sends a probe query and reports latency + sample answer', async () => {
  const kv = new FakeKV();
  const { ctx, env, cookie } = await login(kv);
  const realFetch = globalThis.fetch;
  /** @type {string[]} */
  const urls = [];
  globalThis.fetch = /** @type {any} */ (async (/** @type {any} */ input) => {
    urls.push(String(input));
    return new Response(buildResponse(buildQuery('example.com'), [{ type: 1, rdata: v4rdata('93.184.216.34') }]));
  });

  try {
    const res = await call(ctx, env, '/api/upstream/test', {
      method: 'POST', cookie, body: { preset: 'cloudflare' },
    });
    assert.equal(res.status, 200);
    const j = await res.json();
    assert.equal(j.ok, true);
    assert.equal(j.url, 'https://cloudflare-dns.com/dns-query');
    assert.equal(j.sample, '93.184.216.34');
    assert.equal(typeof j.ms, 'number');
    assert.deepEqual(urls, ['https://cloudflare-dns.com/dns-query']);

    const failing = await call(ctx, env, '/api/upstream/test', {
      method: 'POST', cookie, body: { preset: 'adguard' },
    });
    assert.equal(failing.status, 200, 'a probe failure is a result, not an HTTP error');
  } finally {
    globalThis.fetch = realFetch;
  }
});

// ---- blocklist subscriptions ---------------------------------------------------

test('blocklists: the deploy default is one ordinary, deletable entry', async () => {
  const kv = new FakeKV();
  const { ctx, env, cookie } = await login(kv);
  ctx.blocklist = new Blocklist();
  ctx.blocklist.putSource(DEFAULT_BLOCKLIST_URL, 'a.test\nb.test\n@@e.test\n');

  const res = await call(ctx, env, '/api/blocklists', { cookie });
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.deepEqual(j.subscriptions, [{
    url: DEFAULT_BLOCKLIST_URL,
    entries: 2,
    exceptions: 1,
    loadedAt: ctx.blocklist.loadedAt,
    error: null,
    source: 'deploy',
  }]);
  assert.equal(j.total, 2, 'total is what the memory warning reads');
  assert.equal(j.totalExceptions, 1);
  assert.equal(j.maxUrls, MAX_BLOCKLIST_URLS);
  assert.equal(j.entryLimit, 1_000_000);

  // The same payload rides along with the settings the dashboard boots from.
  const boot = await (await call(ctx, env, '/api/settings', { cookie })).json();
  assert.equal(boot.blocklist.total, 2, 'GET /api/settings carries the panel payload');
});

test('blocklists: POST subscribes, promotes the default, and refuses bad input', async () => {
  const kv = new FakeKV();
  const { ctx, env, cookie } = await login(kv);
  /** @param {string} url */
  const add = (url) => call(ctx, env, '/api/blocklists', { method: 'POST', cookie, body: { url } });

  const first = await add('https://two.test/list');
  assert.equal(first.status, 200);
  const j = await first.json();
  assert.equal(j.subscriptions.length, 2, 'the deploy entry survives the save');
  assert.ok(j.subscriptions.every((/** @type {{source: string}} */ s) => s.source === 'saved'),
    'saving the list turns the deployment default into an ordinary entry');
  assert.deepEqual(
    JSON.parse(kv.data.get('settings:main') ?? '{}').blocklistUrls,
    [DEFAULT_BLOCKLIST_URL, 'https://two.test/list'],
    'the whole effective list is persisted',
  );

  const dup = await add('https://two.test/list');
  assert.equal(dup.status, 400);
  assert.match((await dup.json()).error, /already subscribed/);

  const plain = await add('http://two.test/list');
  assert.equal(plain.status, 400, 'https only');
  assert.match((await plain.json()).error, /https/);

  const empty = await add('   ');
  assert.equal(empty.status, 400);

  for (let i = 0; i < MAX_BLOCKLIST_URLS - 2; i++) await add(`https://l${i}.test/list`);
  const over = await add('https://one-too-many.test/list');
  assert.equal(over.status, 400);
  assert.match((await over.json()).error, new RegExp(`at most ${MAX_BLOCKLIST_URLS}`));
  assert.equal(
    (await (await call(ctx, env, '/api/blocklists', { cookie })).json()).subscriptions.length,
    MAX_BLOCKLIST_URLS,
  );
});

test('blocklists: DELETE unsubscribes — the last one turns the remote list off', async () => {
  const kv = new FakeKV();
  const { ctx, env, cookie } = await login(kv);
  await call(ctx, env, '/api/blocklists', { method: 'POST', cookie, body: { url: 'https://two.test/list' } });

  const drop = await call(ctx, env, `/api/blocklists?url=${encodeURIComponent(DEFAULT_BLOCKLIST_URL)}`, {
    method: 'DELETE', cookie,
  });
  assert.equal(drop.status, 200);
  let j = await drop.json();
  assert.deepEqual(j.subscriptions.map((/** @type {{url: string}} */ s) => s.url), ['https://two.test/list']);

  const missing = await call(ctx, env, '/api/blocklists?url=https://nope.test/list', { method: 'DELETE', cookie });
  assert.equal(missing.status, 404);

  const last = await call(ctx, env, `/api/blocklists?url=${encodeURIComponent('https://two.test/list')}`, {
    method: 'DELETE', cookie,
  });
  j = await last.json();
  assert.deepEqual(j.subscriptions, [], 'no remote blocklist left — a deliberate state');
  assert.equal(JSON.parse(kv.data.get('settings:main') ?? '{}').blocklistUrls.length, 0);
  assert.equal(
    (await (await call(ctx, env, '/api/blocklists', { cookie })).json()).subscriptions.length,
    0,
    'and it stays empty on the next read',
  );
});

test('blocklists: refresh is 501 without the worker hook, 200 with it', async () => {
  const kv = new FakeKV();
  const { ctx, env, cookie } = await login(kv);

  const bare = await call(ctx, env, '/api/blocklists/refresh', { method: 'POST', cookie });
  assert.equal(bare.status, 501);
  assert.match((await bare.json()).error, /refresh not available/);

  /** @type {boolean[]} */ const calls = [];
  ctx.blocklist = new Blocklist();
  ctx.blocklistRefresh = async (force) => { calls.push(force === true); };
  ctx.blocklist.putSource(DEFAULT_BLOCKLIST_URL, 'warm.test\n');

  const reloaded = await call(ctx, env, '/api/blocklists/refresh', { method: 'POST', cookie });
  assert.equal(reloaded.status, 200);
  assert.deepEqual(calls, [true], 'a manual reload forces revalidation');
  assert.equal((await reloaded.json()).total, 1);
});

test('settings: blocklistUrls validation in the patch', async () => {
  const kv = new FakeKV();
  const { ctx, env, cookie } = await login(kv);
  /** @param {unknown} body */
  const post = (body) => call(ctx, env, '/api/settings', { method: 'POST', cookie, body });

  const notArray = await post({ blocklistUrls: 'https://a.test/list' });
  assert.equal(notArray.status, 400);
  assert.match((await notArray.json()).error, /array/);

  const badRow = await post({ blocklistUrls: ['http://a.test/list'] });
  assert.equal(badRow.status, 400, 'one unusable row must not be silently dropped on save');
  assert.match((await badRow.json()).error, /https/);

  const dupe = await post({ blocklistUrls: ['https://a.test/list', 'https://a.test/list'] });
  assert.equal(dupe.status, 400);
  assert.match((await dupe.json()).error, /unique/);

  const reset = await post({ blocklistUrls: null });
  assert.equal(reset.status, 200);
  assert.equal((await reset.json()).settings.blocklistUrls, null, 'null hands control back to the variable');
  assert.equal(JSON.parse(kv.data.get('settings:main') ?? '{}').blocklistUrls, null);
});
