// dashboard.js — JSON API for the dashboard.
//
// The UI itself is a static asset (see assets/index.html), served by the
// [assets] binding in wrangler.toml. This file only handles /api/* routes.
//
// `ctx` (built by worker.js) carries the KV-backed stores and the test fn:
//   { rules, settings, keywords, tlds, testFn }

import { normalizeDomain } from './rules.js';
import { normalizeTld, normalizeKeyword } from './lists.js';
import { clampRetention } from './settings.js';

const SESSION_COOKIE = 'dns_dash_session';

/** @param {Env} env @returns {boolean} */
function isConfigured(env) {
  return typeof env.DASHBOARD_PASSWORD === 'string' && env.DASHBOARD_PASSWORD.length > 0;
}

/** Constant-time-ish string compare.
 * @param {unknown} a @param {unknown} b @returns {boolean}
 */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Session is valid only if the cookie matches the configured password.
 * @param {Request} request
 * @param {Env} env
 * @returns {boolean}
 */
function authOk(request, env) {
  const pw = env.DASHBOARD_PASSWORD;
  if (typeof pw !== 'string') return false;
  const cookie = request.headers.get('cookie') || '';
  const m = cookie.match(/(?:^|;\s*)dns_dash_session=([^;]+)/);
  if (!m) return false;
  return safeEqual(decodeURIComponent(m[1]), pw);
}

/** @param {unknown} body @param {ResponseInit} [init] @returns {Response} */
function json(body, init = {}) {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      ...(init.headers || {}),
    },
  });
}

/** Build ` WHERE a=? AND b=? ` + args from the given filters. */
/** @param {Array<[string, string|null|undefined]>} entries @returns {{where: string, args: string[]}} */
function buildWhere(entries) {
  let where = '';
  const args = [];
  for (const [clause, value] of entries) {
    if (value === '' || value === null || value === undefined) continue;
    where += (where ? ' AND' : ' WHERE') + ' ' + clause;
    args.push(value);
  }
  return { where, args };
}

/** Whitelist + validate a settings object into a patch, or { error }.
 * @param {Record<string, unknown>} source @returns {{patch?: Partial<FilterSettings>, error?: string}}
 */
function settingsPatch(source) {
  /** @type {Partial<FilterSettings>} */
  const patch = {};
  const BOOL_KEYS = /** @type {const} */ (['rebindProtection', 'idnBlock', 'tldBlock', 'keywordBlock', 'logPassed']);
  for (const k of BOOL_KEYS) {
    if (typeof source[k] === 'boolean') patch[k] = source[k]; // k is a boolean key
  }
  if ('logRetentionDays' in source) {
    const days = clampRetention(source.logRetentionDays);
    if (Number.isNaN(days)) return { error: 'logRetentionDays must be a number (0-3650)' };
    patch.logRetentionDays = days;
  }
  return { patch };
}

/** @param {Request} request @param {Env} env @param {URL} url @param {ApiCtx} ctx */
export async function handleApi(request, env, url, ctx) {
  const { rules, settings, keywords, tlds, testFn } = ctx;

  // ---- Login: POST /api/session { password } or Authorization: Bearer <pw> ----
  if (url.pathname === '/api/session' && request.method === 'POST') {
    if (!isConfigured(env)) {
      return json({ error: 'Password not configured', code: 'unconfigured' }, { status: 503 });
    }

    let password = null;
    const auth = request.headers.get('authorization') || '';
    if (auth.startsWith('Bearer ')) password = auth.slice(7);
    if (!password) {
      try {
        const b = await request.json();
        if (b && typeof b.password === 'string') password = b.password;
      } catch { /* non-JSON login body: fall through to reject */ }
    }
    if (!password || typeof env.DASHBOARD_PASSWORD !== 'string' || !safeEqual(password, env.DASHBOARD_PASSWORD)) {
      return json({ error: 'Invalid password' }, { status: 401 });
    }

    const res = json({ ok: true });
    res.headers.append(
      'Set-Cookie',
      `${SESSION_COOKIE}=${encodeURIComponent(env.DASHBOARD_PASSWORD)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`
    );
    return res;
  }

  // ---- Sign out: DELETE /api/session ----
  if (url.pathname === '/api/session' && request.method === 'DELETE') {
    const res = json({ ok: true });
    res.headers.append(
      'Set-Cookie',
      `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
    );
    return res;
  }

  // ---- Everything else requires a valid session ----
  if (!isConfigured(env)) {
    return json({ error: 'Password not configured', code: 'unconfigured' }, { status: 503 });
  }
  if (!authOk(request, env)) {
    // No WWW-Authenticate header -> the browser will NOT show its native
    // username/password dialog. The UI handles 401 itself.
    return json({ error: 'Unauthorized' }, { status: 401 });
  }

  const path = url.pathname;

  // ---- custom rules ----
  if (path === '/api/rules' && request.method === 'GET') {
    await rules.refresh(true);
    return json({ rules: await rules.list() });
  }

  if (path === '/api/rules' && request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'bad json' }, { status: 400 }); }

    const domain = normalizeDomain(body.domain);
    if (!domain) return json({ error: 'invalid domain' }, { status: 400 });
    if (body.kind !== 'allow' && body.kind !== 'deny') {
      return json({ error: 'kind must be allow|deny' }, { status: 400 });
    }

    await rules.put(domain, body.kind);
    return json({ ok: true, domain, kind: body.kind });
  }

  if (path === '/api/rules' && request.method === 'DELETE') {
    const domain = normalizeDomain(url.searchParams.get('domain') || '');
    if (!domain) return json({ error: 'invalid domain' }, { status: 400 });
    const existed = await rules.delete(domain);
    return json({ ok: true, existed });
  }

  if (path === '/api/rules/bulk' && request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'bad json' }, { status: 400 }); }
    if (body.kind !== 'allow' && body.kind !== 'deny') {
      return json({ error: 'kind must be allow|deny' }, { status: 400 });
    }
    if (typeof body.domains !== 'string') {
      return json({ error: 'domains must be a string' }, { status: 400 });
    }

    const entries = [];
    const skipped = [];
    for (const line of body.domains.split(/[\r\n,]+/)) {
      if (!line.trim()) continue;
      entries.push({ domain: line.trim(), kind: body.kind });
    }
    // ONE read + ONE write for the whole batch (not one per rule).
    const added = await rules.putBulk(entries);

    // Report which input lines were unparseable.
    for (const e of entries) {
      if (!normalizeDomain(e.domain)) skipped.push(e.domain);
    }

    return json({ ok: true, added, skipped });
  }

  // ---- test domain: full server-side pipeline (custom rules + blocklist + policies) ----
  if (path === '/api/test' && request.method === 'GET') {
    const domain = normalizeDomain(url.searchParams.get('domain') || '');
    if (!domain) return json({ error: 'invalid domain' }, { status: 400 });
    if (typeof testFn !== 'function') return json({ error: 'test not available' }, { status: 501 });
    return json(await testFn(domain, env));
  }

  // ---- settings (KV, persistent) ----
  if (path === '/api/settings') {
    if (!settings) return json({ error: 'settings not available' }, { status: 501 });

    if (request.method === 'GET') {
      await settings.refresh(true);
      return json({ settings: settings.get() });
    }

    if (request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'bad json' }, { status: 400 }); }

      const { patch, error } = settingsPatch(body);
      if (error) return json({ error }, { status: 400 });
      if (!patch || Object.keys(patch).length === 0) {
        return json({ error: 'no valid settings provided' }, { status: 400 });
      }

      await settings.update(patch);
      return json({ ok: true, settings: settings.get() });
    }
  }

  // ---- config backup: export / import ----
  if (path === '/api/export' && request.method === 'GET') {
    await Promise.all([
      settings.refresh(true),
      rules.refresh(true),
      keywords.refresh(true),
      tlds.refresh(true),
    ]);
    return json({
      version: 1,
      exportedAt: new Date().toISOString(),
      settings: settings.get(),
      rules: await rules.list(),
      keywords: keywords.list(),
      tlds: tlds.list(),
    });
  }

  if (path === '/api/import' && request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'bad json' }, { status: 400 }); }

    const mode = body.mode === 'replace' ? 'replace' : 'merge';
    const MAX_ITEMS = 200_000; // KV value cap is 25 MiB; 200k rows is well under it
    /** @param {unknown} v @returns {any[]|null} */
    const arr = (v) => (Array.isArray(v) ? v.slice(0, MAX_ITEMS) : null);
    const rulesIn = arr(body.rules);
    const kwIn = arr(body.keywords);
    const tldIn = arr(body.tlds);

    if (!rulesIn && !kwIn && !tldIn && !body.settings) {
      return json({ error: 'nothing to import: provide rules, keywords, tlds, or settings' }, { status: 400 });
    }

    /** @type {{mode:'merge'|'replace', rules: {applied:number, skipped:number}|null, keywords: {applied:number, skipped:number}|null, tlds: {applied:number, skipped:number}|null, settings: boolean}} */
    const summary = { mode, rules: null, keywords: null, tlds: null, settings: false };

    if (rulesIn) {
      const valid = rulesIn.filter(
        (e) => e && typeof e.domain === 'string' && (e.kind === 'allow' || e.kind === 'deny'));
      const applied = mode === 'replace'
        ? await rules.replaceAll(valid)
        : await rules.putBulk(valid);
      summary.rules = { applied, skipped: rulesIn.length - valid.length };
    }

    if (kwIn) {
      summary.keywords = mode === 'replace'
        ? await keywords.replaceAll(kwIn, normalizeKeyword)
        : await keywords.addMany(kwIn, normalizeKeyword);
    }
    if (tldIn) {
      summary.tlds = mode === 'replace'
        ? await tlds.replaceAll(tldIn, normalizeTld)
        : await tlds.addMany(tldIn, normalizeTld);
    }

    if (body.settings && typeof body.settings === 'object') {
      const { patch, error } = settingsPatch(body.settings);
      if (error) return json({ error }, { status: 400 });
      if (patch && Object.keys(patch).length) {
        await settings.update(patch);
        summary.settings = true;
      }
    }

    return json({ ok: true, ...summary });
  }

  // ---- filter lists: blocked TLDs + blocked keywords ----
  const listMatch = path.match(/^\/api\/filters\/(keywords|tlds)$/);
  if (listMatch) {
    const isKeywords = listMatch[1] === 'keywords';
    const store = isKeywords ? keywords : tlds;
    const normalize = isKeywords ? normalizeKeyword : normalizeTld;
    if (!store) return json({ error: 'list not available' }, { status: 501 });

    if (request.method === 'GET') {
      return json({ items: store.list() });
    }

    if (request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'bad json' }, { status: 400 }); }
      const value = normalize(body.value === null || body.value === undefined ? body.add : body.value);
      if (!value) return json({ error: 'invalid value' }, { status: 400 });
      const added = await store.add(value);
      return json({ ok: true, added, items: store.list() });
    }

    if (request.method === 'DELETE') {
      const value = normalize(url.searchParams.get('value') || '');
      if (!value) return json({ error: 'invalid value' }, { status: 400 });
      const removed = await store.remove(value);
      return json({ ok: true, removed, items: store.list() });
    }
  }

  // ---- logs (D1) ----
  const isLogsPath = path === '/api/logs' || path.startsWith('/api/logs/');
  if (isLogsPath) {
    const logs = env.LOGS;
    if (!logs) {
      // 501 (not 503) so the frontend doesn't mistake this for "password not configured".
      return json({ error: 'D1 logging not configured', code: 'no_d1' }, { status: 501 });
    }

    // GET /api/logs/stats -> aggregate overview (status mix, top blocked, volume)
    if (path === '/api/logs/stats' && request.method === 'GET') {
      const [byStatus, topBlocked, last24h, total] = await Promise.all([
        logs.prepare('SELECT status, COUNT(*) AS n FROM dns_logs GROUP BY status').all(),
        logs.prepare(
          "SELECT domain, COUNT(*) AS n FROM dns_logs " +
          "WHERE status IN ('deny','blocklist','tld','keyword','rebind','idn') " +
          'GROUP BY domain ORDER BY n DESC LIMIT ?').bind(10).all(),
        logs.prepare(
          'SELECT (ts / 3600000) % 24 AS hour, COUNT(*) AS n FROM dns_logs ' +
          'WHERE ts >= ? GROUP BY hour ORDER BY hour')
          .bind(Date.now() - 24 * 86400000).all(),
        logs.prepare('SELECT COUNT(*) AS n FROM dns_logs').first(),
      ]);
      const buckets = new Array(24).fill(0);
      for (const r of last24h.results) buckets[Number(r.hour)] = Number(r.n);
      return json({
        total: total.n,
        byStatus: { rows: byStatus.results, total: total.n },
        topBlocked: topBlocked.results,
        last24h: buckets,
      });
    }

    // DELETE /api/logs/:id  -> delete one row
    if (path.startsWith('/api/logs/') && request.method === 'DELETE') {
      const id = path.slice('/api/logs/'.length);
      if (!/^\d+$/.test(id)) return json({ error: 'bad id' }, { status: 400 });
      await logs.prepare('DELETE FROM dns_logs WHERE id = ?').bind(parseInt(id, 10)).run();
      return json({ ok: true });
    }

    if (path === '/api/logs') {
      const search = (url.searchParams.get('search') || '').trim();
      const status = url.searchParams.get('status') || '';

      const { where, args } = buildWhere([
        [search ? 'domain LIKE ?' : '', search ? `%${search}%` : ''],
        [status ? 'status = ?' : '', status],
      ]);

      // GET /api/logs?search=&status=&limit=&offset=
      if (request.method === 'GET') {
        const limit = Math.min(parseInt(url.searchParams.get('limit') || '100', 10) || 100, 500);
        const offset = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);

        const total = (await logs
          .prepare('SELECT COUNT(*) AS n FROM dns_logs' + where)
          .bind(...args)
          .first()).n;

        const { results } = await logs
          .prepare('SELECT id, domain, status, filter, qtype, ts FROM dns_logs' + where +
                   ' ORDER BY ts DESC LIMIT ? OFFSET ?')
          .bind(...args, limit, offset)
          .all();

        return json({ logs: results, total });
      }

      // DELETE /api/logs?search=&status=&clear=1  -> delete matching (or all with clear=1)
      if (request.method === 'DELETE') {
        if (!where && url.searchParams.get('clear') !== '1') {
          return json({ error: 'use ?clear=1 to delete all logs' }, { status: 400 });
        }
        await logs.prepare('DELETE FROM dns_logs' + where).bind(...args).run();
        return json({ ok: true });
      }
    }
  }

  return json({ error: 'not found' }, { status: 404 });
}
