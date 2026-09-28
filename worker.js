// worker.js — DoH filter: remote blocklist + custom allow/deny + dashboard
import { Blocklist } from './blocklist.js';
import { RuleStore } from './rules.js';
import { handleApi, serveDashboard } from './dashboard.js';
import {
  Buf,
  parseQuestion,
  buildNxdomainResponse,
  buildRefusedResponse,
  minTtl,
  base64urlDecode,
} from './dns.js';

const BLOCKLIST_URL =
  'https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/pro-plus/domains';
const UPSTREAM = 'https://dns.quad9.net/dns-query';
const DNS_MEDIA_TYPE = 'application/dns-message';
const BLOCKLIST_CACHE_KEY = 'https://blocklist.internal/v1';
const BLOCKLIST_TTL = 6 * 60 * 60; // seconds

// Per-isolate singletons. The RuleStore is backed by env.RULES, which we
// only get per-request, so it's created lazily and memoized per isolate.
const blocklist = new Blocklist();
let ruleStore = null;
let ruleStoreKv = null;

function getRules(env) {
  if (!ruleStore || ruleStoreKv !== env.RULES) {
    ruleStore = new RuleStore(env.RULES);
    ruleStoreKv = env.RULES;
  }
  return ruleStore;
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
 * Decision pipeline for a QNAME:
 *   1. Custom allowlist (KV)     → pass through
 *   2. Custom denylist  (KV)     → NXDOMAIN
 *   3. Remote blocklist          → NXDOMAIN
 *   4. Otherwise                 → forward to Quad9
 */
async function decide(name, env) {
  await getRules(env).refresh();
  const custom = getRules(env).lookup(name);
  if (custom === 'allow') return 'allow';
  if (custom === 'deny') return 'deny';
  if (blocklist.isBlocked(name)) return 'deny';
  return 'pass';
}

async function handleQuery(queryBuf, env) {
  const q = parseQuestion(queryBuf);
  if (!q) return new Response('malformed DNS message', { status: 400 });

  const decision = await decide(q.name, env);

  if (decision === 'deny') {
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

    // ---- dashboard ----
    if (url.pathname === '/dashboard' || url.pathname === '/dashboard/') {
      return serveDashboard();
    }
    if (url.pathname.startsWith('/api/')) {
      return handleApi(request, env, url, getRules(env));
    }

    // ---- health ----
    if (url.pathname === '/healthz') {
      await ensureBlocklist();
      return Response.json({
        ok: true,
        blocklistSize: blocklist.size,
        blocklistLoadedAt: blocklist.loadedAt,
        customRulesCached: getRules(env).cache.size,
      });
    }

    // ---- /dns-query ----
    if (url.pathname !== '/dns-query') {
      return new Response('Not Found', { status: 404 });
    }

    await ensureBlocklist();

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
