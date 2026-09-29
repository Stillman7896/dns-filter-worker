import { Blocklist, BLOCKLIST_URL } from './blocklist.js';
import { RuleStore } from './rules.js';
import { handleApi } from './dashboard.js';
import {
  Buf,
  parseQuestion,
  buildNxdomainResponse,
  buildRefusedResponse,
  minTtl,
  base64urlDecode,
} from './dns.js';

const UPSTREAM = 'https://dns.quad9.net/dns-query';
const DNS_MEDIA_TYPE = 'application/dns-message';
const BLOCKLIST_CACHE_KEY = 'https://blocklist.internal/v1';
const BLOCKLIST_TTL = 24 * 60 * 60; // seconds

// Per-isolate singletons.
const blocklist = new Blocklist();
const ruleStore = new RuleStore(null);
let ruleKv = null;

function ensureRuleKv(env) {
  if (env.RULES !== ruleKv) {
    ruleKv = env.RULES;
    ruleStore.kv = env.RULES;
    ruleStore.cachedVersion = null; // reset cache across binding changes
  }
}

async function ensureBlocklist() {
  if (blocklist.size > 0 && Date.now() - blocklist.loadedAt < BLOCKLIST_TTL * 1000) return;

  const cache = caches.default;
  const cacheKey = new Request(BLOCKLIST_CACHE_KEY);
  let text;
  const cached = await cache.match(cacheKey);
  if (cached) {
    text = await cached.text();
  } else {
    const res = await fetch(BLOCKLIST_URL, { cf: { cacheTtl: BLOCKLIST_TTL } });
    if (!res.ok) throw new Error(`blocklist HTTP ${res.status}`);
    text = await res.text();
    cache.put(cacheKey, new Response(text, {
      headers: { 'Content-Type': 'text/plain', 'Cache-Control': `max-age=${BLOCKLIST_TTL}` },
    }));
  }
  blocklist.load(text);
}

async function forwardToQuad9(queryBuf) {
  const res = await fetch(UPSTREAM, {
    method: 'POST',
    headers: { 'Content-Type': DNS_MEDIA_TYPE, Accept: DNS_MEDIA_TYPE },
    body: queryBuf,
  });
  if (!res.ok) throw new Error(`upstream HTTP ${res.status}`);
  return Buf.from(await res.arrayBuffer());
}

/**
 * Decision pipeline for a QNAME.
 * Returns { status, filter }:
 *   status: 'allow' | 'deny' | 'blocklist' | 'none'
 *   filter: 'allowlist' | 'denylist' | 'blocklist' | 'upstream'
 */
async function decide(name, env) {
  await ruleStore.refresh();
  const custom = ruleStore.lookup(name);
  if (custom === 'allow') return { status: 'allow', filter: 'allowlist' };
  if (custom === 'deny') return { status: 'deny', filter: 'denylist' };
  if (blocklist.isBlocked(name)) return { status: 'blocklist', filter: 'blocklist' };
  return { status: 'none', filter: 'upstream' };
}

/**
 * Full pipeline test for the "Test domain" tab. Reports which layer decided
 * and the exact rule/blocklist entry that matched.
 */
async function testDomain(domain) {
  await ensureBlocklist();
  await ruleStore.refresh();

  const custom = ruleStore.match(domain); // { kind, at } | null
  const blockHit = blocklist.match(domain); // entry | null

  let status, filter, matched = null;
  if (custom && custom.kind === 'allow') {
    status = 'allow'; filter = 'allowlist'; matched = custom.at;
  } else if (custom && custom.kind === 'deny') {
    status = 'deny'; filter = 'denylist'; matched = custom.at;
  } else if (blockHit) {
    status = 'blocklist'; filter = 'blocklist'; matched = blockHit;
  } else {
    status = 'none'; filter = 'upstream';
  }

  return { domain, status, filter, matched, blocklistSize: blocklist.size };
}

// ---- D1 audit logging ----
let logsReady = false;
const LOGS_CREATE =
  'CREATE TABLE IF NOT EXISTS dns_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, status TEXT NOT NULL, filter TEXT NOT NULL, ts INTEGER NOT NULL)';

/**
 * Insert one audit row. Never throws — logging must not break DNS responses.
 */
async function logQuery(env, domain, status, filter) {
  if (!env.LOGS) return;
  try {
    if (!logsReady) {
      await env.LOGS.prepare(LOGS_CREATE).run();
      logsReady = true;
    }
    await env.LOGS
      .prepare('INSERT INTO dns_logs (domain, status, filter, ts) VALUES (?, ?, ?, ?)')
      .bind(domain, status, filter, Date.now())
      .run();
  } catch (e) {
    console.error('[logs] insert failed:', e.message);
  }
}

async function handleQuery(queryBuf, env) {
  const q = parseQuestion(queryBuf);
  if (!q) return new Response('malformed DNS message', { status: 400 });

  const { status, filter } = await decide(q.name, env);

  // Audit logging (fire and forget the DB write).
  await logQuery(env, q.name, status, filter);

  if (status === 'deny' || status === 'blocklist') {
    return new Response(buildNxdomainResponse(queryBuf), {
      headers: { 'Content-Type': DNS_MEDIA_TYPE, 'Cache-Control': 'max-age=30' },
    });
  }

  try {
    const upstream = await forwardToQuad9(queryBuf);
    return new Response(upstream, {
      headers: {
        'Content-Type': DNS_MEDIA_TYPE,
        'Cache-Control': `max-age=${minTtl(upstream)}`,
      },
    });
  } catch {
    return new Response(buildRefusedResponse(queryBuf), {
      status: 502,
      headers: { 'Content-Type': DNS_MEDIA_TYPE },
    });
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ---- dashboard API ----
    if (url.pathname.startsWith('/api/')) {
      ensureRuleKv(env);
      return handleApi(request, env, url, ruleStore, testDomain);
    }

    // ---- health ----
    if (url.pathname === '/healthz') {
      await ensureBlocklist();
      ensureRuleKv(env);
      return Response.json({
        ok: true,
        blocklistSize: blocklist.size,
        blocklistLoadedAt: blocklist.loadedAt,
        customRulesCached: ruleStore.cache.size,
        dashboardConfigured: typeof env.DASHBOARD_PASSWORD === 'string' && env.DASHBOARD_PASSWORD.length > 0,
      });
    }

    // ---- /dns-query ----
    if (url.pathname !== '/dns-query') {
      // Not an API/health/DNS path -> serve static dashboard assets.
      if (env.ASSETS) return env.ASSETS.fetch(request);
      return new Response('Not Found', { status: 404 });
    }

    await ensureBlocklist();
    ensureRuleKv(env);

    if (request.method === 'GET') {
      const accept = request.headers.get('accept') || '';
      if (!accept.includes(DNS_MEDIA_TYPE) && !accept.includes('*/*')) {
        return new Response(`Accept must include ${DNS_MEDIA_TYPE}`, { status: 406 });
      }
      const b64 = url.searchParams.get('dns');
      if (!b64) return new Response('missing ?dns=', { status: 400 });
      const buf = base64urlDecode(b64);
      if (!buf) return new Response('bad base64url', { status: 400 });
      return handleQuery(buf, env);
    }

    if (request.method === 'POST') {
      const ct = request.headers.get('content-type') || '';
      if (!ct.startsWith(DNS_MEDIA_TYPE)) {
        return new Response(`expected ${DNS_MEDIA_TYPE}`, { status: 415 });
      }
      const raw = await request.arrayBuffer();
      if (raw.byteLength === 0 || raw.byteLength > 4096) {
        return new Response('bad body', { status: 400 });
      }
      return handleQuery(Buf.from(new Uint8Array(raw)), env);
    }

    return new Response('Method Not Allowed', { status: 405 });
  },
};
