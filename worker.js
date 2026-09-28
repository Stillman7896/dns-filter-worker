
import { Blocklist } from './blocklist.js';
import {
  parseQuestion,
  buildNxdomainResponse,
  buildRefusedResponse,
  minTtl,
} from './dns.js';

const BLOCKLIST_URL =
  'https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/pro-plus/domains';
const UPSTREAM = 'https://dns.quad9.net/dns-query';
const DNS_MEDIA_TYPE = 'application/dns-message';
const BLOCKLIST_CACHE_KEY = 'https://blocklist.internal/v1';
const BLOCKLIST_TTL = 24 * 60 * 60; // seconds

const blocklist = new Blocklist();

async function ensureBlocklist() {
  // In-memory fast path: already loaded in this isolate
  if (blocklist.size > 0 && Date.now() - blocklist.loadedAt < BLOCKLIST_TTL * 1000) {
    return;
  }

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
    // Store in edge cache for other isolates
    const toCache = new Response(text, {
      headers: {
        'Content-Type': 'text/plain',
        'Cache-Control': `max-age=${BLOCKLIST_TTL}`,
      },
    });
    // Don't await — fire and forget
    cache.put(cacheKey, toCache.clone());
  }

  blocklist.load(text);
}

function cacheHeaders(buf) {
  return {
    'Content-Type': DNS_MEDIA_TYPE,
    'Cache-Control': `max-age=${minTtl(buf)}`,
  };
}

async function forwardToQuad9(queryBuf) {
  const res = await fetch(UPSTREAM, {
    method: 'POST',
    headers: { 'Content-Type': DNS_MEDIA_TYPE, Accept: DNS_MEDIA_TYPE },
    body: queryBuf,
  });
  if (!res.ok) throw new Error(`upstream HTTP ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

async function handleQuery(queryBuf, ctx) {
  const q = parseQuestion(queryBuf);
  if (!q) return new Response('malformed DNS message', { status: 400 });

  if (blocklist.isBlocked(q.name)) {
    return new Response(buildNxdomainResponse(queryBuf), {
      headers: { 'Content-Type': DNS_MEDIA_TYPE, 'Cache-Control': 'max-age=30' },
    });
  }

  try {
    const upstream = await forwardToQuad9(queryBuf);
    return new Response(upstream, { headers: cacheHeaders(upstream) });
  } catch (err) {
    return new Response(buildRefusedResponse(queryBuf), {
      status: 502,
      headers: { 'Content-Type': DNS_MEDIA_TYPE },
    });
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/healthz') {
      await ensureBlocklist();
      return Response.json({
        ok: true,
        blocklistSize: blocklist.size,
        blocklistLoadedAt: blocklist.loadedAt,
      });
    }

    if (url.pathname !== '/dns-query') {
      return new Response('Not Found', { status: 404 });
    }

    // Kick off blocklist load lazily; do it once.
    await ensureBlocklist();

    if (request.method === 'GET') {
      const b64 = url.searchParams.get('dns');
      if (!b64) return new Response('missing ?dns=', { status: 400 });
      const buf = base64urlDecode(b64);
      if (!buf) return new Response('bad base64url', { status: 400 });
      return handleQuery(buf, ctx);
    }

    if (request.method === 'POST') {
      const ct = request.headers.get('content-type') || '';
      if (!ct.startsWith(DNS_MEDIA_TYPE)) {
        return new Response(`expected ${DNS_MEDIA_TYPE}`, { status: 415 });
      }
      const buf = new Uint8Array(await request.arrayBuffer());
      if (buf.byteLength === 0 || buf.byteLength > 4096) {
        return new Response('bad body', { status: 400 });
      }
      return handleQuery(buf, ctx);
    }

    return new Response('Method Not Allowed', { status: 405 });
  },
};

// ---- base64url helpers (Workers has atob/btoa, but no Buffer) ----
function base64urlDecode(str) {
  try {
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}
