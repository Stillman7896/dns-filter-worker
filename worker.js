// worker.js — DoH filter
// Query path: qclass guard -> custom allowlist -> denylist -> blocklist
//           -> blocked TLD -> blocked keyword -> rebinding -> IDN -> upstream
// Response path: answer-level rebinding check (private IPs)
//
// Runtime-configurable: env.BLOCKLIST_URL / env.UPSTREAM_URL (wrangler [vars])
// with defaults from blocklist.js / DEFAULT_UPSTREAM_URL below.

import { Blocklist, DEFAULT_BLOCKLIST_URL } from './blocklist.js';
import { RuleStore } from './rules.js';
import { SettingsStore } from './settings.js';
import { TextSetStore } from './lists.js';
import { runQueryFilters, privateAnswerIP, BLOCKED_QUERY_STATUSES } from './filters.js';
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
const PRUNE_EVERY = 500; // opportunistic D1 retention batch size

// ---- Per-isolate singletons (one shared KV namespace) ----
const blocklist = new Blocklist();
const ruleStore = new RuleStore(null);
const settingsStore = new SettingsStore(null);
const keywordStore = new TextSetStore(null, 'keywords:data');
const tldStore = new TextSetStore(null, 'tlds:data');
const stores = { ruleStore, blocklist, keywordStore, tldStore };

let boundKv = null;
let loadedBlocklistUrl = null;

function ensureKv(env) {
  if (env.RULES === boundKv) return;
  boundKv = env.RULES;
  // Binding changed -> different namespace: drop ALL in-memory state so a
  // warm TTL cache can never serve the previous binding's rules/settings.
  ruleStore.bind(env.RULES);
  settingsStore.bind(env.RULES);
  keywordStore.bind(env.RULES);
  tldStore.bind(env.RULES);
}

async function ensureBlocklist(env) {
  const blUrl = env.BLOCKLIST_URL || DEFAULT_BLOCKLIST_URL;
  const fresh =
    blocklist.size > 0 &&
    loadedBlocklistUrl === blUrl &&
    Date.now() - blocklist.loadedAt < BLOCKLIST_STALE_MS;
  if (fresh) return;

  // Cache key derives from the configured URL so switching BLOCKLIST_URL
  // never serves a stale cached copy.
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

/** Refresh every KV-backed store. All TTL-cached, so this is usually free. */
async function refreshStores() {
  await Promise.all([
    settingsStore.refresh(),
    ruleStore.refresh(),
    keywordStore.refresh(),
    tldStore.refresh(),
  ]);
}

// ---- D1 audit logging ----

let logsReady = false;
let logsMigrated = false;
let logCount = 0;

const LOGS_CREATE =
  'CREATE TABLE IF NOT EXISTS dns_logs (' +
  'id INTEGER PRIMARY KEY AUTOINCREMENT, ' +
  'domain TEXT NOT NULL, ' +
  'status TEXT NOT NULL, ' +
  'filter TEXT NOT NULL, ' +
  'ts INTEGER NOT NULL, ' +
  'qtype INTEGER)';

/** Never throws — logging must not break DNS responses. */
async function logQuery(env, domain, status, filter, qtype, retentionDays) {
  if (!env.LOGS) return;
  try {
    if (!logsReady) {
      await env.LOGS.prepare(LOGS_CREATE).run();
      logsReady = true;
    }
    if (!logsMigrated) {
      // Tables created before qtype existed lack the column. CREATE TABLE
      // IF NOT EXISTS no-ops on them; a fresh table then errors with
      // "duplicate column" here, which we swallow.
      try { await env.LOGS.prepare('ALTER TABLE dns_logs ADD COLUMN qtype INTEGER').run(); }
      catch { /* already present */ }
      logsMigrated = true;
    }
    await env.LOGS
      .prepare('INSERT INTO dns_logs (domain, status, filter, ts, qtype) VALUES (?, ?, ?, ?, ?)')
      .bind(domain, status, filter, Date.now(), qtype == null ? null : qtype)
      .run();

    logCount++;
    // Configured retention: opportunistically prune rows past the cutoff.
    // Throttled to every PRUNE_EVERY inserts so the extra write only fires
    // on a busy isolate, never on a cold query.
    if (retentionDays > 0 && logCount % PRUNE_EVERY === 0) {
      await env.LOGS
        .prepare('DELETE FROM dns_logs WHERE ts < ?')
        .bind(Date.now() - retentionDays * 86400000)
        .run();
    }
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

function refused(queryBuf, maxAge = 30) {
  return new Response(buildRefusedResponse(queryBuf), {
    headers: { 'Content-Type': DNS_MEDIA_TYPE, 'Cache-Control': `max-age=${maxAge}` },
  });
}

/** Upstream unreachable: SERVFAIL-ish (502) carrying a REFUSED answer. */
function upstreamFailure(queryBuf) {
  return new Response(buildRefusedResponse(queryBuf), {
    status: 502,
    headers: { 'Content-Type': DNS_MEDIA_TYPE, 'Cache-Control': 'max-age=15' },
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

  // Only the IN class belongs on this resolver (blocks CH/version.bind
  // probing and other non-IN queries before any store I/O). No log row: this
  // is a wire-level reject, not a domain filtering decision.
  if (q.qclass !== 1) return refused(queryBuf, 60);

  await refreshStores();
  const settings = settingsStore.get();
  const verdict = runQueryFilters(stores, settings, q.name);
  const retention = settings.logRetentionDays;

  if (BLOCKED_QUERY_STATUSES.has(verdict.status)) {
    await logQuery(env, q.name, verdict.status, verdict.filter, q.qtype, retention);
    return nxdomain(queryBuf);
  }

  // allow | none -> forward upstream
  try {
    const upstream = await forwardToUpstream(queryBuf, env);

    if (verdict.status === 'none' && settings.rebindProtection) {
      const priv = privateAnswerIP(upstream);
      if (priv) {
        await logQuery(env, q.name, 'rebind', 'rebind', q.qtype, retention);
        return nxdomain(queryBuf);
      }
    }
    await logQuery(env, q.name, verdict.status, verdict.filter, q.qtype, retention);
    return passThrough(upstream);
  } catch {
    // Upstream unavailable — never break DNS.
  }

  await logQuery(env, q.name, verdict.status, verdict.filter, q.qtype, retention);
  return upstreamFailure(queryBuf);
}

// ---- Test endpoint (mirrors the live pipeline) ----

async function testDomain(domain, env) {
  await ensureBlocklist(env);
  await refreshStores();

  const settings = settingsStore.get();
  const verdict = runQueryFilters(stores, settings, domain);
  return {
    domain,
    status: verdict.status,
    filter: verdict.filter,
    matched: verdict.matched,
    blocklistSize: blocklist.size,
    note:
      verdict.status === 'none' && settings.rebindProtection
        ? 'answer-level rebinding check applies after upstream resolves'
        : null,
  };
}

// ---- Worker entry ----

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    ensureKv(env);

    // ---- dashboard API ----
    if (url.pathname.startsWith('/api/')) {
      return handleApi(request, env, url, {
        rules: ruleStore,
        keywords: keywordStore,
        tlds: tldStore,
        blocklist,
        settings: settingsStore,
        testFn: testDomain,
      });
    }

    // ---- health ----
    if (url.pathname === '/healthz') {
      await Promise.all([ensureBlocklist(env), refreshStores()]);
      return Response.json({
        ok: true,
        blocklistSize: blocklist.size,
        blocklistLoadedAt: blocklist.loadedAt,
        customRules: ruleStore.rules.size,
        keywords: keywordStore.get().size,
        blockedTlds: tldStore.get().size,
        settings: settingsStore.get(),
        blocklistUrl: env.BLOCKLIST_URL || DEFAULT_BLOCKLIST_URL,
        upstreamUrl: env.UPSTREAM_URL || DEFAULT_UPSTREAM_URL,
        dashboardConfigured:
          typeof env.DASHBOARD_PASSWORD === 'string' && env.DASHBOARD_PASSWORD.length > 0,
      });
    }

    // ---- root redirect for browsers ----
    if (url.pathname === '/') {
      const accept = request.headers.get('accept') || '';
      if (accept.includes('text/html')) {
        return Response.redirect(new URL('/dashboard', request.url).toString(), 302);
      }
    }

    // ---- /dns-query ----
    if (url.pathname !== '/dns-query') {
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