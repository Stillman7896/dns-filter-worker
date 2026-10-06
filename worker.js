import { Blocklist, DEFAULT_BLOCKLIST_URL } from './blocklist.js';
import { RuleStore } from './rules.js';
import { SettingsStore } from './settings.js';
import { handleApi } from './dashboard.js';
import {
  Buf,
  parseQuestion,
  buildNxdomainResponse,
  buildRefusedResponse,
  minTtl,
  base64urlDecode,
} from './dns.js';

const DEFAULT_UPSTREAM_URL = 'https://dns.quad9.net/dns-query';
const DNS_MEDIA_TYPE = 'application/dns-message';
const BLOCKLIST_STALE_MS = 6 * 60 * 60 * 1000; // 6h

// ---- DNS rebinding: internal / special-use names (RFC 6761/6762) ----
const REBIND_LOCAL_NAMES = new Set([
  'localhost', 'localhost.localdomain', 'ip6-localhost', 'ip6-loopback',
]);
const INTERNAL_TLDS = new Set([
  'local', 'localdomain', 'lan', 'home', 'internal', 'intranet', 'corp',
  'private', 'home.arpa', 'test', 'invalid', 'example', 'localhost',
]);

// ---- Per-isolate singletons ----
const blocklist = new Blocklist();
const ruleStore = new RuleStore(null);
const settingsStore = new SettingsStore(null);
let ruleKv = null;
let loadedBlocklistUrl = null;

function ensureRuleKv(env) {
  if (env.RULES !== ruleKv) {
    ruleKv = env.RULES;
    ruleStore.kv = env.RULES;
    ruleStore.cachedVersion = null; // reset cache across binding changes
    settingsStore.kv = env.RULES;
    settingsStore.loaded = false;   // reload settings for the new binding
  }
}

async function ensureBlocklist(env) {
  const blUrl = env.BLOCKLIST_URL || DEFAULT_BLOCKLIST_URL;
  const fresh =
    blocklist.size > 0 &&
    loadedBlocklistUrl === blUrl &&
    Date.now() - blocklist.loadedAt < BLOCKLIST_STALE_MS;
  if (fresh) return;

  // Cache key derives from the configured URL so switching BLOCKLIST_URL
  // never serves a stale cached list.
  const cacheKey = new Request(blUrl);
  let text;
  const cached = await caches.default.match(cacheKey);
  if (cached) {
    text = await cached.text();
  } else {
    const cacheTtl = Math.floor(BLOCKLIST_STALE_MS / 1000);
    const res = await fetch(blUrl, { cf: { cacheTtl } });
    if (!res.ok) throw new Error(`blocklist HTTP ${res.status}`);
    text = await res.text();
    caches.default.put(cacheKey, new Response(text, {
      headers: { 'Content-Type': 'text/plain', 'Cache-Control': `max-age=${cacheTtl}` },
    }));
  }
  blocklist.load(text);
  loadedBlocklistUrl = blUrl;
}

async function forwardToUpstream(queryBuf, env) {
  const upstream = env.UPSTREAM_URL || DEFAULT_UPSTREAM_URL;
  const res = await fetch(upstream, {
    method: 'POST',
    headers: { 'Content-Type': DNS_MEDIA_TYPE, Accept: DNS_MEDIA_TYPE },
    body: queryBuf,
  });
  if (!res.ok) throw new Error(`upstream HTTP ${res.status}`);
  return Buf.from(await res.arrayBuffer());
}

// ---- Filter helpers (query-level) ----

/** Returns the internal TLD / name that matched, or null. */
function rebindNameHit(name) {
  if (REBIND_LOCAL_NAMES.has(name)) return name;
  const dot = name.lastIndexOf('.');
  const tld = dot === -1 ? name : name.slice(dot + 1);
  return INTERNAL_TLDS.has(tld) ? tld : null;
}

/**
 * IDN homograph detection — "block all or off" strategy:
 * any punycode (xn--) label, or any label with non-ASCII bytes
 * (raw UTF-8 sent by non-compliant clients). Returns the offending
 * label, or null if clean.
 */
function idnHit(name) {
  let start = 0;
  for (;;) {
    const dot = name.indexOf('.', start);
    const label = dot === -1 ? name.slice(start) : name.slice(start, dot);
    if (label.startsWith('xn--')) return label;
    if (dot === -1) break;
    start = dot + 1;
  }
  if (/[\x80-\uffff]/.test(name)) return '<non-ascii>';
  return null;
}

/**
 * Ordered query-side decision chain (sync — stores must be refreshed first).
 * Returns { status, filter, matched }.
 */
function runQueryFilters(settings, name) {
  const custom = ruleStore.match(name);
  if (custom) {
    return custom.kind === 'allow'
      ? { status: 'allow', filter: 'allowlist', matched: custom.at }
      : { status: 'deny',  filter: 'denylist',  matched: custom.at };
  }

  const blockHit = blocklist.match(name);
  if (blockHit) return { status: 'blocklist', filter: 'blocklist', matched: blockHit };

  if (settings.rebindProtection) {
    const hit = rebindNameHit(name);
    if (hit) return { status: 'rebind', filter: 'rebind', matched: hit };
  }
  if (settings.idnBlock) {
    const hit = idnHit(name);
    if (hit) return { status: 'idn', filter: 'idn', matched: hit };
  }

  return { status: 'none', filter: 'upstream', matched: null };
}

// ---- DNS rebinding: answer-level private IP inspection ----

const BLOCKED_QUERY_STATUSES = new Set(['deny', 'blocklist', 'rebind', 'idn']);

function rd16(b, o) { return ((b[o] & 0xff) << 8) | (b[o + 1] & 0xff); }

function isPrivateV4(b, o) {
  const ip = ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  if ((ip >>> 24) === 10) return true;                              // 10/8
  if ((ip >>> 20) === (0xac100000 >>> 20)) return true;             // 172.16/12
  if ((ip >>> 16) === 0xc0a8) return true;                          // 192.168/16
  if ((ip >>> 24) === 127) return true;                             // 127/8
  if ((ip >>> 16) === 0xa9fe) return true;                          // 169.254/16 (metadata)
  if ((ip >>> 22) === (0x64400000 >>> 22)) return true;             // 100.64/10 (CGNAT)
  return ip === 0;
}

function isPrivateV6(b, o) {
  // ::
  let allZero = true;
  for (let i = o; i < o + 16; i++) if (b[i]) { allZero = false; break; }
  if (allZero) return true;
  // ::1
  let z = true;
  for (let i = o; i < o + 15; i++) if (b[i]) { z = false; break; }
  if (z && b[o + 15] === 1) return true;
  // fc00::/7, fe80::/10
  if ((b[o] & 0xfe) === 0xfc) return true;
  if (b[o] === 0xfe && (b[o + 1] & 0xc0) === 0x80) return true;
  // ::ffff:0:0/96 (v4-mapped) -> embedded IPv4
  let mapped = true;
  for (let i = o; i < o + 10; i++) if (b[i]) { mapped = false; break; }
  if (mapped && b[o + 10] === 0xff && b[o + 11] === 0xff) return isPrivateV4(b, o + 12);
  return false;
}

function skipNameAt(buf, off) {
  let jumps = 0;
  while (off < buf.length) {
    const len = buf[off];
    if (len === 0) return off + 1;
    if ((len & 0xc0) === 0xc0) return off + 2; // compression pointer
    off += 1 + len;
    if (++jumps > 255) return -1;
  }
  return -1;
}

function fmtV4(b, o) { return `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`; }

/** Walk the ANSWER section; return the first private IP string or null. */
function privateAnswerIP(buf) {
  if (!buf || buf.length < 12) return null;
  const qd = rd16(buf, 4);
  const an = rd16(buf, 6);
  let off = 12;

  for (let i = 0; i < qd; i++) {
    const r = skipNameAt(buf, off);
    if (r < 0) return null;
    off = r + 4;
    if (off > buf.length) return null;
  }

  for (let i = 0; i < an; i++) {
    const r = skipNameAt(buf, off);
    if (r < 0) return null;
    if (r + 10 > buf.length) return null;
    const type = rd16(buf, r);
    const rdlen = rd16(buf, r + 8);
    const rd = r + 10;
    if (type === 1 && rdlen === 4 && isPrivateV4(buf, rd)) return fmtV4(buf, rd);
    if (type === 28 && rdlen === 16 && isPrivateV6(buf, rd)) return '<private-v6>';
    off = rd + rdlen;
    if (off > buf.length) return null;
  }
  return null;
}

// ---- D1 audit logging ----

let logsReady = false;
const LOGS_CREATE =
  'CREATE TABLE IF NOT EXISTS dns_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, status TEXT NOT NULL, filter TEXT NOT NULL, ts INTEGER NOT NULL)';

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

// ---- Response builders ----

function nxdomain(queryBuf) {
  return new Response(buildNxdomainResponse(queryBuf), {
    headers: { 'Content-Type': DNS_MEDIA_TYPE, 'Cache-Control': 'max-age=30' },
  });
}

function passThrough(upstream) {
  return new Response(upstream, {
    headers: {
      'Content-Type': DNS_MEDIA_TYPE,
      'Cache-Control': `max-age=${minTtl(upstream)}`,
    },
  });
}

// ---- Main query handler ----

async function handleQuery(queryBuf, env) {
  const q = parseQuestion(queryBuf);
  if (!q) return new Response('malformed DNS message', { status: 400 });

  await settingsStore.refresh();
  const settings = settingsStore.get();
  const verdict = runQueryFilters(settings, q.name);

  if (BLOCKED_QUERY_STATUSES.has(verdict.status)) {
    await logQuery(env, q.name, verdict.status, verdict.filter);
    return nxdomain(queryBuf);
  }

  // allow | none -> forward upstream
  try {
    const upstream = await forwardToUpstream(queryBuf, env);

    if (verdict.status === 'allow' || verdict.status === 'none') {
      // Answer-level rebinding check applies to non-allowlisted names.
      if (verdict.status === 'none' && settings.rebindProtection) {
        const priv = privateAnswerIP(upstream);
        if (priv) {
          await logQuery(env, q.name, 'rebind', 'rebind');
          return nxdomain(queryBuf);
        }
      }
      await logQuery(env, q.name, verdict.status, verdict.filter);
      return passThrough(upstream);
    }
  } catch {
    // Upstream unavailable — never break DNS.
  }

  await logQuery(env, q.name, verdict.status, verdict.filter);
  return new Response(buildRefusedResponse(queryBuf), {
    status: 502,
    headers: { 'Content-Type': DNS_MEDIA_TYPE },
  });
}

// ---- Test endpoint (mirrors the live pipeline) ----

async function testDomain(domain, env) {
  await ensureBlocklist(env);
  await ruleStore.refresh();
  await settingsStore.refresh();

  const verdict = runQueryFilters(settingsStore.get(), domain);
  return {
    domain,
    status: verdict.status,
    filter: verdict.filter,
    matched: verdict.matched,
    blocklistSize: blocklist.size,
    note:
      verdict.status === 'none' && settingsStore.get().rebindProtection
        ? 'answer-level rebinding check applies after upstream resolves'
        : null,
  };
}

// ---- Worker entry ----

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    ensureRuleKv(env);

    // ---- dashboard API ----
    if (url.pathname.startsWith('/api/')) {
      return handleApi(request, env, url, ruleStore, testDomain, settingsStore);
    }

    // ---- health ----
    if (url.pathname === '/healthz') {
      await Promise.all([ensureBlocklist(env), settingsStore.refresh()]);
      return Response.json({
        ok: true,
        blocklistSize: blocklist.size,
        blocklistLoadedAt: blocklist.loadedAt,
        customRulesCached: ruleStore.cache.size,
        settings: settingsStore.get(),
        blocklistUrl: env.BLOCKLIST_URL || DEFAULT_BLOCKLIST_URL,
        upstreamUrl: env.UPSTREAM_URL || DEFAULT_UPSTREAM_URL,
        dashboardConfigured:
          typeof env.DASHBOARD_PASSWORD === 'string' && env.DASHBOARD_PASSWORD.length > 0,
      });
    }

    // ---- root redirect for browsers (curl without Accept: text/html passes through) ----
    if (url.pathname === '/') {
      const accept = request.headers.get('accept') || '';
      if (accept.includes('text/html')) {
        return Response.redirect(new URL('/dashboard', request.url).toString(), 302);
      }
    }

    // ---- /dns-query ----
    if (url.pathname !== '/dns-query') {
      // Not an API/health/DNS path -> serve static dashboard assets.
      if (env.ASSETS) return env.ASSETS.fetch(request);
      return new Response('Not Found', { status: 404 });
    }

    await ensureBlocklist(env);

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
