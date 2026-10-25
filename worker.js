// worker.js — DoH filter
// Query path: qclass guard -> response route -> answer cache -> custom
//           allowlist -> denylist -> blocklist -> blocked TLD -> blocked
//           keyword -> regex -> rebinding -> IDN -> upstream -> answer-level
//           rebinding
// Response path: answers cached under a normalized key (config epoch + name +
//           type + DO bit), transaction ID patched per client on hits.
//
// Runtime selection: the upstream provider and the per-domain response routes
// come from dashboard settings in KV. `env.UPSTREAM_URL` is the fallback for a
// deployment with no provider picked; `env.BLOCKLIST_URL` is still a var.

import { Blocklist, effectiveBlocklistUrls, MAX_SOURCE_BYTES, BLOCKLIST_ENTRY_LIMIT, MAX_BLOCKLIST_URLS } from './blocklist.js';
import { RuleStore, RULES_KEY, LEGACY_RULE_PREFIX } from './rules.js';
import { SettingsStore, SETTINGS_KEY } from './settings.js';
import { RouteStore, routeRecords, ROUTES_KEY } from './routing.js';
import { TextSetStore, normalizeKeyword, normalizeRegex, DATA_VERSION_KEY } from './lists.js';
import { runQueryFilters, privateAnswerIP, BLOCKED_QUERY_STATUSES, RegexEngine } from './filters.js';
import { resolveUpstream, resolveFallback } from './upstream.js';
import { odohForward } from './odoh.js';
import { handleApi, isConfigured, safeEqual } from './dashboard.js';
import {
  Buf,
  parseQuestion,
  buildNxdomainResponse,
  buildRefusedResponse,
  buildAnswerResponse,
  minTtl,
  base64urlDecode,
  ednsDo,
} from './dns.js';

const DNS_MEDIA_TYPE = 'application/dns-message';
const BLOCKLIST_STALE_MS = 24 * 60 * 60 * 1000; // 24h fresh window
const BLOCKLIST_FETCH_TTL = Math.floor(BLOCKLIST_STALE_MS / 1000);
const FETCHED_AT_HEADER = 'x-blocklist-fetched-at';
const BLOCKED_MAX_AGE = 300; // filter-list / policy blocks: rarely unblocked
const RULE_MAX_AGE = 30;     // custom allow/deny: user edits stay snappy
const NEGATIVE_MAX_AGE = 60; // NXDOMAIN/NODATA from upstream: short, re-checks soon
const RESP_CACHE_MAX = 2048; // isolate answer-cache cap (entries)
const CACHE_ORIGIN = 'https://answer.cache/';
const PRUNE_EVERY = 500; // opportunistic D1 retention batch size

// ---- Per-isolate singletons (one shared KV namespace) ----
const blocklist = new Blocklist();
const ruleStore = new RuleStore(/** @type {KVLike} */ (/** @type {unknown} */ (null)));
const settingsStore = new SettingsStore(/** @type {KVLike} */ (/** @type {unknown} */ (null)));
const routeStore = new RouteStore(/** @type {KVLike} */ (/** @type {unknown} */ (null)));
const keywordStore = new TextSetStore(/** @type {KVLike} */ (/** @type {unknown} */ (null)), 'keywords:data', normalizeKeyword);
const regexStore = new TextSetStore(/** @type {KVLike} */ (/** @type {unknown} */ (null)), 'regex:data', normalizeRegex);
const regexEngine = new RegexEngine(regexStore);
const tldStore = new TextSetStore(/** @type {KVLike} */ (/** @type {unknown} */ (null)), 'tlds:data');
const stores = { ruleStore, blocklist, keywordStore, regex: regexEngine, tldStore, routeStore };

/** @type {KVLike|null} */
let boundKv = null;

/** @param {Env} env */
function ensureKv(env) {
  const kv = env.RULES ?? null;
  if (kv === boundKv) return;
  boundKv = kv;
  // Binding changed (or removed) -> different namespace: drop ALL in-memory
  // state so a warm TTL cache can never serve the previous binding's
  // rules/settings.
  ruleStore.bind(/** @type {KVLike} */ (kv));
  settingsStore.bind(/** @type {KVLike} */ (kv));
  routeStore.bind(/** @type {KVLike} */ (kv));
  keywordStore.bind(/** @type {KVLike} */ (kv));
  regexStore.bind(/** @type {KVLike} */ (kv));
  tldStore.bind(/** @type {KVLike} */ (kv));
}

/**
 * Keep `work` off the response path when an ExecutionContext exists
 * (`waitUntil`), or inline when there is none (tests, healthz callers).
 * Always returns a settled-never-rejecting promise; safe to `await`.
 * @param {ExecutionContext|undefined} ctx
 * @param {Promise<unknown>} work
 * @returns {Promise<unknown>|undefined}
 */
function bg(ctx, work) {
  const safe = Promise.resolve(work).catch((e) => {
    console.error('[bg] failed:', e instanceof Error ? e.message : e);
  });
  if (ctx && typeof ctx.waitUntil === 'function') {
    ctx.waitUntil(safe);
    return undefined;
  }
  return safe;
}

/** Cache lookup that never throws (no Cache API in some test harnesses). */
/** @param {Request} req @returns {Promise<Response|undefined>} */
async function matchCache(req) {
  try {
    return (await caches.default.match(req)) || undefined;
  } catch {
    return undefined;
  }
}

/**
 * The subscriptions this deployment runs: the saved list, or the BLOCKLIST_URL
 * variable as its single entry until the user saves one (see blocklist.js).
 * @param {Env} env
 * @returns {Promise<string[]>}
 */
async function blocklistUrls(env) {
  await settingsStore.refresh(); // cheap: TTL-cached, shared data:version read
  return effectiveBlocklistUrls(settingsStore.get(), env);
}

/**
 * Free-plan ceiling guard: a document over MAX_SOURCE_BYTES costs more to split
 * and parse than the entire per-request CPU budget. It is refused *before* the
 * parse, and whatever copy is already answering queries stays in service.
 * @param {string} blUrl @param {string} text @returns {boolean} true when safe to parse
 */
function withinSourceBudget(blUrl, text) {
  if (text.length <= MAX_SOURCE_BYTES) return true;
  const mb = (text.length / 1048576).toFixed(1);
  blocklist.sourceRejected(
    blUrl,
    `document is ${mb} MB, over the ${MAX_SOURCE_BYTES / 1048576} MB per-list cap — parse skipped to stay inside the CPU budget`
  );
  return false;
}

/**
 * Reset credential: `Authorization: Bearer <pw>`, `X-Reset-Token: <pw>`, or a
 * `{"password": "<pw>"}` body. The dashboard password doubles as the reset
 * token, so the hatch needs no second secret to manage.
 * @param {Request} request @returns {Promise<string>}
 */
async function resetToken(request) {
  const auth = request.headers.get('authorization') || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7);
  const header = request.headers.get('x-reset-token');
  if (header) return header;
  try {
    const body = await request.json();
    if (body && typeof body.password === 'string') return body.password;
  } catch { /* not a JSON body */ }
  return '';
}

/**
 * Conditional fetch of ONE blocklist document: revalidates on its stored ETag,
 * refreshes the edge copy with a new freshness marker, and parses a changed
 * body into that subscription's set.
 * @param {string} blUrl
 * @param {{etag: string|null, text: string|null}} prev `text` null = nothing to re-store
 * @param {ExecutionContext} [ctx]
 */
async function fetchBlocklistSource(blUrl, prev, ctx) {
  const cacheKey = new Request(blUrl);
  const headers = prev.etag ? { 'If-None-Match': prev.etag } : undefined;
  const res = await fetch(blUrl, { headers, cf: { cacheTtl: BLOCKLIST_FETCH_TTL } });

  let text = prev.text;
  if (res.status === 304) {
    // Same document as the copy already held: a body-less revalidation only
    // moves the freshness marker; a stale-while-revalidate one re-stores it.
    blocklist.touchSource(blUrl);
  } else if (res.ok) {
    text = await res.text();
    if (!withinSourceBudget(blUrl, text)) return; // refused before it costs a parse
    blocklist.putSource(blUrl, text);
  } else {
    throw new Error(`blocklist HTTP ${res.status} for ${blUrl}`);
  }

  if (text === null) return; // no body in hand to put back in the edge cache

  /** @type {Record<string, string>} */
  const putHeaders = {
    'Content-Type': 'text/plain',
    'Cache-Control': `max-age=${BLOCKLIST_FETCH_TTL}`,
    [FETCHED_AT_HEADER]: String(Date.now()),
  };
  const etag = res.headers.get('etag') || prev.etag;
  if (etag) putHeaders['ETag'] = etag;
  bg(ctx, caches.default.put(cacheKey, new Response(text, { headers: putHeaders })));
}

/**
 * Load ONE subscription with zero blocking work when a usable copy exists:
 * fresh source -> nothing; edge copy -> serve it (past its 24h window it is
 * revalidated in the background); cold colo -> blocking fetch. A failed
 * refresh leaves the last good copy in place (stale-if-error).
 * @param {string} blUrl
 * @param {boolean} force revalidate against the origin now, whatever the clock says
 * @param {ExecutionContext} [ctx]
 * @returns {Promise<void>}
 */
async function ensureBlocklistSource(blUrl, force, ctx) {
  const cacheKey = new Request(blUrl);

  if (force) {
    // Manual reload from the dashboard: conditional, so an unchanged list
    // costs one 304 and keeps the copy already parsed.
    const cached = await matchCache(cacheKey);
    const etag = cached?.headers.get('etag') || null;
    await fetchBlocklistSource(blUrl, { etag, text: null }, ctx);
    if (!blocklist.sourceLoaded(blUrl) && cached) {
      const text = await cached.text();
      if (withinSourceBudget(blUrl, text)) blocklist.putSource(blUrl, text);
    }
    return;
  }

  if (blocklist.sourceFresh(blUrl, BLOCKLIST_STALE_MS)) return;

  const cached = await matchCache(cacheKey);
  if (cached) {
    const text = await cached.text();
    if (!withinSourceBudget(blUrl, text)) return;
    const fetchedAt = Number(cached.headers.get(FETCHED_AT_HEADER)) || 0;
    const etag = cached.headers.get('etag');
    blocklist.putSource(blUrl, text);
    // Stale-while-revalidate: answer with the old copy while it refreshes.
    if (Date.now() - fetchedAt >= BLOCKLIST_STALE_MS && ctx) {
      bg(ctx, fetchBlocklistSource(blUrl, { etag, text }, ctx));
    }
    return;
  }

  // Cold colo: nothing cached anywhere -> the fetch must block this request.
  await fetchBlocklistSource(blUrl, { etag: null, text: null }, ctx);
}

/**
 * Load every subscribed blocklist. A single failing document is recorded on
 * its source (the dashboard shows it) and keeps its last good copy; only when
 * NO document could be loaded at all does this throw, so one dead host never
 * leaves the resolver without a list it used to have.
 * @param {Env} env
 * @param {ExecutionContext} [ctx]
 * @param {boolean} [force] revalidate every subscription now
 * @returns {Promise<void>}
 */
async function ensureBlocklist(env, ctx, force = false) {
  const urls = await blocklistUrls(env);
  blocklist.setSources(urls);
  if (!urls.length) return; // the user deleted every subscription: no remote list

  const pending = force ? urls : urls.filter((u) => !blocklist.sourceFresh(u, BLOCKLIST_STALE_MS));
  if (!pending.length) return;

  const settled = await Promise.allSettled(pending.map((u) => ensureBlocklistSource(u, force, ctx)));
  /** @type {unknown} */ let firstError = null;
  let failures = 0;
  for (let i = 0; i < pending.length; i++) {
    const result = settled[i];
    if (result.status === 'fulfilled') continue;
    failures++;
    if (!firstError) firstError = result.reason;
    const message = result.reason instanceof Error ? result.reason.message : String(result.reason);
    blocklist.sourceError(pending[i], message);
  }
  if (failures === pending.length && !blocklist.size) throw firstError || new Error('blocklist unavailable');
}

/**
 * Forward a query to ONE upstream and return its answer bytes.
 * @param {Uint8Array} queryBuf
 * @param {{kind: 'doh'|'odoh', url: string, relay?: string}} upstream
 * @returns {Promise<Uint8Array>}
 */
async function askUpstream(queryBuf, upstream) {
  if (upstream.kind === 'odoh') return odohForward(upstream.url, upstream.relay || '', queryBuf);
  const res = await fetch(upstream.url, {
    method: 'POST',
    headers: { 'Content-Type': DNS_MEDIA_TYPE, Accept: DNS_MEDIA_TYPE },
    body: queryBuf,
  });
  if (!res.ok) throw new Error(`upstream HTTP ${res.status}`);
  return Buf.from(await res.arrayBuffer());
}

// Rcodes that mean "this server couldn't answer", not "the name is bad":
// SERVFAIL and REFUSED. NXDOMAIN and NOERROR/NODATA are real answers.
const UPSTREAM_BAD_RC = new Set([2, 5]);

/**
 * Forward to the primary upstream, falling back to a secondary DoH server
 * when the primary is unreachable, errors, or answers SERVFAIL/REFUSED.
 * `fallback` is null when failover is switched off (settings or deployment).
 * @param {Uint8Array} queryBuf
 * @param {ReturnType<typeof resolveUpstream>} upstream
 * @param {ReturnType<typeof resolveFallback>} fallback
 * @returns {Promise<Uint8Array>}
 */
async function forwardToUpstream(queryBuf, upstream, fallback) {
  /** @type {Uint8Array|null} */ let primary = null;
  try {
    primary = await askUpstream(queryBuf, upstream);
  } catch { /* unreachable: the fallback below decides */ }

  if (!fallback) {
    if (primary) return primary;
    throw new Error('upstream unreachable');
  }
  if (primary && !UPSTREAM_BAD_RC.has(primary[3] & 0x0f)) return primary;

  try {
    return await askUpstream(queryBuf, { kind: 'doh', url: fallback.url });
  } catch {
    if (primary) return primary; // the fallback is broken; the primary's answer stands
    throw new Error('upstream and fallback unreachable');
  }
}

/** Refresh every KV-backed store. All TTL-cached, so this is usually free. */
/** @returns {Promise<void>} */
async function refreshStores() {
  await Promise.all([
    settingsStore.refresh(),
    ruleStore.refresh(),
    routeStore.refresh(),
    keywordStore.refresh(),
    regexStore.refresh(),
    tldStore.refresh(),
  ]);
}

/** Every store re-read right now: the reset path must not wait out a TTL window. */
/** @returns {Promise<void>} */
async function forceRefreshStores() {
  await Promise.all([
    settingsStore.refresh(true),
    ruleStore.refresh(true),
    routeStore.refresh(true),
    keywordStore.refresh(true),
    regexStore.refresh(true),
    tldStore.refresh(true),
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
  'qtype INTEGER, ' +
  'client TEXT)';

/** Never throws — logging must not break DNS responses. */
/**
 * @param {Env} env
 * @param {string} domain
 * @param {string} status
 * @param {string} filter
 * @param {string|number} qtype 'unknown' for nxdomain/refused paths
 * @param {number} retentionDays
 * @param {string|null} client tag from the DoH URL, null when untagged
 */
async function logQuery(env, domain, status, filter, qtype, retentionDays, client) {
  if (!env.LOGS) return;
  try {
    if (!logsReady) {
      await env.LOGS.prepare(LOGS_CREATE).run();
      logsReady = true;
    }
    if (!logsMigrated) {
      // Tables created before qtype/client existed lack the columns.
      // CREATE TABLE IF NOT EXISTS no-ops on them; ALTER then errors with
      // "duplicate column" on anything already present, which we swallow.
      for (const col of ['qtype INTEGER', 'client TEXT']) {
        try { await env.LOGS.prepare(`ALTER TABLE dns_logs ADD COLUMN ${col}`).run(); }
        catch { /* column already present */ }
      }
      logsMigrated = true;
    }
    await env.LOGS
      .prepare('INSERT INTO dns_logs (domain, status, filter, ts, qtype, client) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(domain, status, filter, Date.now(), qtype === null || qtype === undefined ? null : qtype, client)
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
    console.error('[logs] insert failed:', e instanceof Error ? e.message : e);
  }
}

// ---- Response builders ----

/** @param {Uint8Array} queryBuf @param {number} [maxAge] @returns {Response} */
function refused(queryBuf, maxAge = 30) {
  return new Response(buildRefusedResponse(queryBuf), {
    headers: { 'Content-Type': DNS_MEDIA_TYPE, 'Cache-Control': `max-age=${maxAge}` },
  });
}

/** Upstream unreachable: SERVFAIL-ish (502) carrying a REFUSED answer. */
/** @param {Uint8Array} queryBuf @returns {Response} */
function upstreamFailure(queryBuf) {
  return new Response(buildRefusedResponse(queryBuf), {
    status: 502,
    headers: { 'Content-Type': DNS_MEDIA_TYPE, 'Cache-Control': 'max-age=15' },
  });
}

// ---- Answer cache (isolate LRU in front of the edge cache) ----
// Keyed by config epoch + QNAME + QTYPE + DNSSEC-OK bit: cache hits survive
// across clients (the transaction ID is patched per query), and any rule or
// filter-toggle change rotates the epoch so a stale verdict is never served.

/** @type {Map<string, {bytes: Uint8Array, cacheControl: string, expiresAt: number}>} */
const respLru = new Map();

/** @param {string} epoch @param {string} name @param {number} qtype @param {boolean} dnssec */
function answerCacheKey(epoch, name, qtype, dnssec) {
  return 'v1|' + epoch + '|' + name + '|' + qtype + '|' + (dnssec ? 'd' : 's');
}

/** Epoch covering every setting that can change a verdict (rules share data:version). */
/** @param {FilterSettings} settings @param {ReturnType<typeof resolveUpstream>} upstream @param {ReturnType<typeof resolveFallback>} fallback @returns {string} */
function configEpoch(settings, upstream, fallback) {
  return (ruleStore.version || '0') +
    '.' + (settings.rebindProtection ? 1 : 0) +
    (settings.idnBlock ? 1 : 0) +
    (settings.tldBlock ? 1 : 0) +
    (settings.keywordBlock ? 1 : 0) +
    (settings.regexBlock ? 1 : 0) +
    // Changing provider must never serve answers cached from the old one.
    '|' + upstream.kind + '|' + upstream.url + '|' + upstream.relay +
    // Failover changes which server answers, so it rotates the epoch too.
    '|' + (fallback ? fallback.url : 'off') +
    // Subscribing, replacing or dropping a list changes what a name resolves
    // to, so a verdict cached under the old set must never be served again.
    '|bl:' + (Array.isArray(settings.blocklistUrls) ? settings.blocklistUrls.join(',') : 'default');
}

/**
 * Cache TTL for an upstream answer: NXDOMAIN and NODATA (NOERROR with zero
 * answer records) are cached briefly — long enough to cut upstream load,
 * short enough to pick up a new record — anything else honours its own
 * record TTLs via minTtl().
 * @param {Uint8Array} answer @returns {number} seconds
 */
function answerTtl(answer) {
  const rcode = answer[3] & 0x0f;
  const answers = (answer[6] << 8) | answer[7];
  if (rcode === 3 || (rcode === 0 && answers === 0)) return NEGATIVE_MAX_AGE;
  return minTtl(answer);
}

/**
 * Response for a client with transaction ID `qid` — cached payloads come from
 * a different message, so the header ID is always rewritten.
 * @param {Uint8Array} bytes @param {string} cacheControl @param {number} qid @returns {Response}
 */
function clientResponse(bytes, cacheControl, qid) {
  const out = bytes.slice();
  out[0] = (qid >>> 8) & 0xff;
  out[1] = qid & 0xff;
  return new Response(out, {
    headers: { 'Content-Type': DNS_MEDIA_TYPE, 'Cache-Control': cacheControl },
  });
}

/** Note: maxAge/age are seconds; LRU touches re-insert for recency. */
/** @param {string} key @param {Uint8Array} bytes @param {string} cacheControl @param {number} maxAge @param {number} age */
function lruPut(key, bytes, cacheControl, maxAge, age) {
  respLru.delete(key);
  respLru.set(key, {
    bytes,
    cacheControl,
    expiresAt: Date.now() + Math.max(0, maxAge - age) * 1000,
  });
  while (respLru.size > RESP_CACHE_MAX) {
    respLru.delete(/** @type {string} */ (respLru.keys().next().value));
  }
}

/**
 * Answer lookup: isolate LRU first, then the edge cache (promoted into the
 * LRU). Null on miss; `qid` patched on every hit.
 * @param {string} key @param {number} qid @returns {Promise<Response|null>}
 */
async function cachedAnswer(key, qid) {
  const hit = respLru.get(key);
  if (hit) {
    if (hit.expiresAt > Date.now()) {
      respLru.delete(key);
      respLru.set(key, hit); // recency touch
      return clientResponse(hit.bytes, hit.cacheControl, qid);
    }
    respLru.delete(key);
  }

  const res = await matchCache(new Request(CACHE_ORIGIN + encodeURIComponent(key)));
  if (!res) return null;
  const bytes = new Uint8Array(await res.arrayBuffer());
  if (bytes.length < 12) return null;
  const cacheControl = res.headers.get('cache-control') || 'max-age=60';
  const maxAge = Number(/max-age=(\d+)/.exec(cacheControl)?.[1]) || 0;
  const age = Number(res.headers.get('age')) || 0;
  lruPut(key, bytes, cacheControl, maxAge, age);
  return clientResponse(bytes, cacheControl, qid);
}

/**
 * Deliver answer bytes, caching them under `key` for `maxAge` seconds in both
 * cache tiers (a falsy key or zero TTL skips caching entirely).
 * @param {Uint8Array} bytes @param {string} key @param {number} maxAge
 * @param {ExecutionContext} [ctx]
 * @returns {Promise<Response>}
 */
async function respond(bytes, key, maxAge, ctx) {
  const ttl = Math.max(0, Math.floor(maxAge));
  const cacheControl = `max-age=${ttl}`;
  if (key && ttl > 0) {
    lruPut(key, bytes, cacheControl, ttl, 0);
    await bg(ctx, caches.default.put(
      new Request(CACHE_ORIGIN + encodeURIComponent(key)),
      new Response(bytes, { headers: { 'Content-Type': DNS_MEDIA_TYPE, 'Cache-Control': cacheControl } }),
    ));
  }
  return new Response(bytes, {
    headers: { 'Content-Type': DNS_MEDIA_TYPE, 'Cache-Control': cacheControl },
  });
}

// ---- Main query handler ----

/** A tag is 1-63 chars of [a-z0-9_-], lowercased; the first char is a letter/digit. */
const TAG_RE = /^[a-z0-9](?:[a-z0-9_-]{0,62})$/;

/**
 * Client tag next to the DoH URL: `?tag=` wins over a `/dns-query/<tag>`
 * suffix. Returns the tag, null when the request is untagged, or undefined
 * when whatever was sent cannot be a tag (caller replies 400).
 * @param {URL} url @returns {string|null|undefined}
 */
function clientTag(url) {
  const param = (url.searchParams.get('tag') || '').trim().toLowerCase();
  if (param) return TAG_RE.test(param) ? param : undefined;
  const m = url.pathname.match(/^\/dns-query\/([^/?]+)$/);
  if (!m) return null;
  let raw;
  try { raw = decodeURIComponent(m[1]); } catch { return undefined; }
  raw = raw.trim().toLowerCase();
  return TAG_RE.test(raw) ? raw : undefined;
}

/**
 * @param {Uint8Array} queryBuf @param {Env} env @param {ExecutionContext} [ctx]
 * @param {string|null} client
 * @returns {Promise<Response>}
 */
async function handleQuery(queryBuf, env, ctx, client = null) {
  const q = parseQuestion(queryBuf);
  if (!q) return new Response('malformed DNS message', { status: 400 });

  // Only the IN class belongs on this resolver (blocks CH/version.bind
  // probing and other non-IN queries before any store I/O). No log row: this
  // is a wire-level reject, not a domain filtering decision.
  if (q.qclass !== 1) return refused(queryBuf, 60);

  await refreshStores();
  const settings = settingsStore.get();
  const retention = settings.logRetentionDays;
  const logPassed = settings.logPassed !== false; // tolerate pre-toggle blobs
  const upstream = resolveUpstream(settings, env);
  const fallback = resolveFallback(upstream, settings, env);

  const key = answerCacheKey(configEpoch(settings, upstream, fallback), q.name, q.qtype, ednsDo(queryBuf));
  const qid = (queryBuf[0] << 8) | queryBuf[1];
  const hit = await cachedAnswer(key, qid);
  if (hit) {
    // Filters still run on a hit (pure in-memory) so the audit log is
    // identical whether an answer came from cache or upstream.
    const verdict = runQueryFilters(stores, settings, q.name);
    if (BLOCKED_QUERY_STATUSES.has(verdict.status) || logPassed) {
      await bg(ctx, logQuery(env, q.name, verdict.status, verdict.filter, q.qtype, retention, client));
    }
    return hit;
  }

  const verdict = runQueryFilters(stores, settings, q.name);

  // A response route is a direct answer: no upstream, no cache miss, and it
  // outranks every block layer (that is why the user set it).
  if (verdict.route) {
    await bg(ctx, logQuery(env, q.name, 'route', 'route', q.qtype, retention, client));
    const records = routeRecords(verdict.route, q.name, q.qtype);
    return respond(buildAnswerResponse(queryBuf, records), key, verdict.route.ttl, ctx);
  }

  if (BLOCKED_QUERY_STATUSES.has(verdict.status)) {
    await bg(ctx, logQuery(env, q.name, verdict.status, verdict.filter, q.qtype, retention, client));
    const maxAge = verdict.filter === 'denylist' ? RULE_MAX_AGE : BLOCKED_MAX_AGE;
    return respond(buildNxdomainResponse(queryBuf), key, maxAge, ctx);
  }

  // allow | none -> forward upstream
  try {
    const answer = await forwardToUpstream(queryBuf, upstream, fallback);

    if (verdict.status === 'none' && settings.rebindProtection) {
      const priv = privateAnswerIP(answer);
      if (priv) {
        await bg(ctx, logQuery(env, q.name, 'rebind', 'rebind', q.qtype, retention, client));
        // Every answer can differ here; never cache the verdict (TTL only
        // tells the client not to re-ask before re-resolving).
        return respond(buildNxdomainResponse(queryBuf), '', RULE_MAX_AGE, ctx);
      }
    }
    if (logPassed) {
      await bg(ctx, logQuery(env, q.name, verdict.status, verdict.filter, q.qtype, retention, client));
    }
    return respond(answer, key, answerTtl(answer), ctx);
  } catch {
    // Upstream unavailable — never break DNS.
  }

  if (logPassed) {
    await bg(ctx, logQuery(env, q.name, verdict.status, verdict.filter, q.qtype, retention, client));
  }
  return upstreamFailure(queryBuf);
}

// ---- Test endpoint (mirrors the live pipeline) ----

/** @param {string} domain @param {Env} env @param {ExecutionContext} [ctx] @returns {Promise<unknown>} */
async function testDomain(domain, env, ctx) {
  await ensureBlocklist(env, ctx);
  await refreshStores();

  const settings = settingsStore.get();
  const verdict = runQueryFilters(stores, settings, domain);
  return {
    domain,
    status: verdict.status,
    filter: verdict.filter,
    matched: verdict.matched,
    blocklistSize: blocklist.size,
    route: verdict.route || null,
    note:
      verdict.route
        ? 'answered locally from a response route — the upstream is never asked'
        : verdict.status === 'none' && settings.rebindProtection
          ? 'answer-level rebinding check applies after upstream resolves'
          : null,
  };
}

/**
 * Warm blocklist + stores concurrently. Returns an error Response when the
 * blocklist cannot be loaded at all (cold fetch failed, no usable copy),
 * null when the worker is ready to answer.
 * @param {Env} env @param {ExecutionContext} [ctx] @returns {Promise<Response|null>}
 */
async function ensureReady(env, ctx) {
  try {
    await Promise.all([ensureBlocklist(env, ctx), refreshStores()]);
    return null;
  } catch (e) {
    console.error('[boot] blocklist unavailable:', e instanceof Error ? e.message : e);
    return new Response('blocklist unavailable', { status: 503 });
  }
}

/**
 * Await `work` and turn a rejection into a one-line problem, so a health probe
 * reports *why* it is degraded instead of throwing past the reader.
 * @param {Promise<unknown>} work @param {string} label
 * @returns {Promise<string|null>}
 */
async function settle(work, label) {
  try {
    await work;
    return null;
  } catch (e) {
    return `${label}: ${e instanceof Error ? e.message : String(e)}`;
  }
}

// ---- Worker entry ----

export default {
  /** @param {Request} request @param {Env} env @param {ExecutionContext} [ctx] */
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    ensureKv(env);

    // ---- dashboard API ----
    if (url.pathname.startsWith('/api/')) {
      return handleApi(request, env, url, {
        rules: ruleStore,
        routes: routeStore,
        keywords: keywordStore,
        regex: regexStore,
        tlds: tldStore,
        blocklist,
        settings: settingsStore,
        // The dashboard's blocklist panel: cheap while the lists are fresh,
        // and `force` revalidates every subscription against its origin.
        blocklistRefresh: (force) => ensureBlocklist(env, ctx, force === true),
        testFn: (domain, e) => testDomain(domain, /** @type {Env} */ (e || env), ctx),
      });
    }

    // ---- escape hatch: wipe the KV configuration without the dashboard ----
    // Defense for a deployment whose own configuration blew its CPU or memory
    // budget: /api/* is unreachable then, but this route touches no store and
    // needs only the dashboard password, so one curl restores a worker that
    // boots again. Deployment variables and the D1 query log are left alone.
    if (url.pathname === '/healthz/reset' && request.method === 'POST') {
      if (!isConfigured(env)) {
        return Response.json({ error: 'reset is not armed: set DASHBOARD_PASSWORD to use it' }, { status: 403 });
      }
      const token = await resetToken(request);
      if (!token || !safeEqual(token, /** @type {string} */ (env.DASHBOARD_PASSWORD))) {
        return Response.json({ error: 'wrong reset token' }, { status: 401 });
      }
      if (!env.RULES) return Response.json({ error: 'no KV binding to reset' }, { status: 400 });

      const cleared = [];
      for (const key of [SETTINGS_KEY, RULES_KEY, ROUTES_KEY, 'keywords:data', 'regex:data', 'tlds:data', DATA_VERSION_KEY]) {
        try {
          await env.RULES.delete(key);
          cleared.push(key);
        } catch { /* keep clearing the rest */ }
      }

      // Legacy one-key-per-rule rows are re-imported on the next read and would
      // quietly undo the reset, so they go as well.
      /** @type {string[]} */ const legacy = [];
      try {
        /** @type {string|undefined} */ let cursor;
        do {
          const page = await env.RULES.list({ prefix: LEGACY_RULE_PREFIX, cursor });
          for (const k of page.keys) legacy.push(k.name);
          cursor = page.list_complete ? undefined : (page.cursor ?? undefined);
        } while (cursor);
      } catch { /* no list support: the blob key above is the one that matters */ }
      for (const name of legacy) {
        try {
          await env.RULES.delete(name);
          cleared.push(name);
        } catch { /* best effort */ }
      }

      await forceRefreshStores();
      return Response.json({
        ok: true,
        cleared,
        note: 'settings and custom rules cleared; deployment variables untouched',
      });
    }

    // ---- health ----
    if (url.pathname === '/healthz') {
      // Health must answer even when degraded: a failed blocklist load or
      // store refresh is reported in the body instead of escaping as an
      // opaque 500 — /dns-query fails for exactly the same reason, so the
      // probe is where that reason has to be visible.
      const problems = (
        await Promise.all([
          settle(ensureBlocklist(env, ctx), 'blocklist unavailable'),
          settle(refreshStores(), 'stores unavailable'),
        ])
      ).filter((p) => p !== null);
      const settings = settingsStore.get();
      const upstream = resolveUpstream(settings, env);
      const fallback = resolveFallback(upstream, settings, env);
      const urls = effectiveBlocklistUrls(settings, env);
      return Response.json({
        ok: problems.length === 0,
        problems,
        blocklistSize: blocklist.size,
        blocklistExceptions: blocklist.exceptionSize,
        blocklistSources: blocklist.listSources(),
        blocklistLoadedAt: blocklist.loadedAt,
        customRules: ruleStore.rules.size,
        routes: routeStore.routes.size,
        keywords: keywordStore.get().size,
        regexRules: regexStore.get().size,
        blockedTlds: tldStore.get().size,
        settings,
        blocklistUrl: urls[0] || '',
        blocklistUrls: urls,
        upstream,
        upstreamUrl: upstream.url,
        fallback: fallback ? { label: fallback.label, url: fallback.url, source: fallback.source } : null,
        blocklistUrlLimit: MAX_BLOCKLIST_URLS,
        blocklistEntryLimit: BLOCKLIST_ENTRY_LIMIT,
        resetArmed: isConfigured(env),
        dashboardConfigured:
          typeof env.DASHBOARD_PASSWORD === 'string' && env.DASHBOARD_PASSWORD.length > 0,
      }, { status: problems.length === 0 ? 200 : 503 });
    }

    // ---- root redirect for browsers ----
    if (url.pathname === '/') {
      const accept = request.headers.get('accept') || '';
      if (accept.includes('text/html')) {
        return Response.redirect(new URL('/dashboard', request.url).toString(), 302);
      }
    }

    // ---- /dns-query, optionally suffixed with the client tag ----
    const dnsPath = url.pathname.match(/^\/dns-query(?:\/([^/?]+))?$/);
    if (!dnsPath) {
      if (env.ASSETS) return env.ASSETS.fetch(request);
      return new Response('Not Found', { status: 404 });
    }
    // `?tag=phone` or `/dns-query/phone` labels the client in the query log;
    // an unusable tag fails fast so a typo never silently logs as untagged.
    const tag = clientTag(url);
    if (tag === undefined) {
      return new Response('invalid client tag: use 1-63 chars of a-z 0-9 - _', { status: 400 });
    }

    if (request.method === 'GET') {
      const accept = request.headers.get('accept') || '';
      if (!accept.includes(DNS_MEDIA_TYPE) && !accept.includes('*/*')) {
        return new Response(`Accept must include ${DNS_MEDIA_TYPE}`, { status: 406 });
      }
      const b64 = url.searchParams.get('dns');
      if (!b64) return new Response('missing ?dns=', { status: 400 });
      const buf = base64urlDecode(b64);
      if (!buf) return new Response('bad base64url', { status: 400 });
      // Validation first: malformed requests never pay for a blocklist load.
      const ready = await ensureReady(env, ctx);
      if (ready) return ready;
      return handleQuery(buf, env, ctx, tag);
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
      const ready = await ensureReady(env, ctx);
      if (ready) return ready;
      return handleQuery(Buf.from(new Uint8Array(raw)), env, ctx, tag);
    }

    return new Response('Method Not Allowed', { status: 405 });
  },
};
