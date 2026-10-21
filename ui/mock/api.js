// Dev-only stand-in for the worker's /api/* routes (see dashboard.js).
// Keeps the same routes, payload shapes and, importantly, the same auth flow:
// everything is 401 until /api/session accepts a password.

import { UPSTREAM_PRESETS, findPreset, probeUpstream, resolveUpstream } from '../../upstream.js';
import { normalizeRoute } from '../../routing.js';
import { normalizeTld, normalizeKeyword, normalizeRegex } from '../../lists.js';
import { normalizeDomain } from '../../rules.js';
import { toUnicode } from '../../idn.js';

const SESSION_COOKIE = 'dns_dash_session';
const PASSWORD = 'demo';

const statusPool = [
  ['none', 62], ['allow', 6], ['blocklist', 18], ['deny', 5],
  ['tld', 3], ['keyword', 4], ['rebind', 1], ['idn', 1],
];

const fixtures = {
  rules: [
    { domain: 'ads.example.net', kind: 'deny' },
    { domain: 'cdn.internal.example.com', kind: 'deny' },
    { domain: 'updates.acme.io', kind: 'allow' },
    { domain: 'metrics.vendor.io', kind: 'deny' },
    { domain: 'releases.example.com', kind: 'allow' },
    { domain: 'beacon.partner.dev', kind: 'deny' },
  ],
  routes: [
    { domain: 'nas.home.lan', type: 'a', value: '192.168.1.20', ttl: 300 },
    { domain: 'media.example.com', type: 'cname', value: 'nas.home.lan', ttl: 300 },
  ],
  keywords: ['doubleclick', 'metrics-gateway', 'telemetry'],
  regex: ['cdn\\d+\\.example\\.com'],
  tlds: ['zip', 'mov', 'xyz'],
  settings: {
    rebindProtection: true,
    idnBlock: false,
    tldBlock: true,
    keywordBlock: true,
    regexBlock: true,
    logPassed: true,
    logRetentionDays: 30,
    upstreamPreset: 'cloudflare',
    upstreamUrl: '',
    upstreamRelay: '',
  },
  logs: [],
};

// Deterministic PRNG so screenshots and manual testing stay stable.
function mulberry(seed) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function seedLogs() {
  const rnd = mulberry(20261017);
  const domains = [
    'doubleclick.net', 'graph.facebook.com', 'updates.acme.io', 'cdn.example.com',
    'telemetry.vendor.io', 'beacon.partner.dev', 'fonts.gstatic.com', 'ads.example.net',
    'metrics-gateway.corp.dev', 'registry.npmjs.org', 'mail.provider.co', 'log.vendor.io',
  ];
  const total = statusPool.reduce((n, [, w]) => n + w, 0);
  const now = Date.now();
  const out = [];
  for (let i = 0; i < 260; i++) {
    let r = rnd() * total;
    let status = 'none';
    for (const [s, w] of statusPool) {
      if ((r -= w) <= 0) { status = s; break; }
    }
    const blockedish = ['deny', 'blocklist', 'tld', 'keyword', 'regex', 'rebind', 'idn'].includes(status);
    const filter =
      status === 'deny' ? 'custom denylist'
        : status === 'blocklist' ? 'hagezi basic'
          : status === 'tld' ? 'blocked tlds'
            : status === 'keyword' ? 'blocked keywords'
              : status === 'regex' ? 'regex rules'
                : status === 'rebind' ? 'rebinding'
                  : status === 'idn' ? 'idn'
                    : status === 'allow' ? 'custom allowlist'
                      : 'upstream';
    const clients = ['laptop', 'phone', 'phone', 'tv', null, null, null];
    out.push({
      id: i + 1,
      domain: domains[Math.floor(rnd() * domains.length)],
      status,
      filter,
      qtype: [1, 1, 1, 28, 65, 99][Math.floor(rnd() * 6)],
      client: clients[Math.floor(rnd() * clients.length)],
      ts: now - Math.floor(rnd() * 72 * 3600 * 1000),
      blocked: blockedish,
    });
  }
  out.sort((a, b) => b.ts - a.ts);
  return out;
}
fixtures.logs = seedLogs();

function json(res, status, body, extraHeaders = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      try { resolve(raw ? JSON.parse(raw) : {}); } catch { resolve(null); }
    });
  });
}

// Same filter semantics as the worker: domain search, status, exact client tag
// or untagged=1 for rows logged without a tag.
function logMatcher(url) {
  const search = (url.searchParams.get('search') || '').trim().toLowerCase();
  const status = url.searchParams.get('status') || '';
  const client = (url.searchParams.get('client') || '').trim().toLowerCase();
  const untagged = url.searchParams.get('untagged') === '1';
  return (r) =>
    (!search || r.domain.includes(search)) &&
    (!status || r.status === status) &&
    (!client || r.client === client) &&
    (!untagged || r.client === null || r.client === undefined);
}

function authed(req) {
  return /(?:^|;\s*)dns_dash_session=1(;|$)/.test(req.headers.cookie || '');
}

export function mockApi(req, res, next) {
  const url = new URL(req.url, 'http://localhost');
  if (!url.pathname.startsWith('/api/')) return next();

  const run = async () => {
    const p = url.pathname;
    const body = ['POST', 'PUT'].includes(req.method) ? await readBody(req) : {};

    if (p === '/api/session' && req.method === 'POST') {
      if ((body || {}).password === PASSWORD) {
        json(res, 200, { ok: true }, {
          'Set-Cookie': `${SESSION_COOKIE}=1; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`,
        });
      } else {
        json(res, 401, { error: 'Invalid password' });
      }
      return;
    }

    if (p === '/api/session' && req.method === 'DELETE') {
      return json(res, 200, { ok: true }, {
        'Set-Cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
      });
    }

    if (!authed(req)) {
      json(res, 401, { error: 'Unauthorized' });
      return;
    }

    // ---- rules ----
    if (p === '/api/rules' && req.method === 'GET') {
      json(res, 200, { rules: fixtures.rules });
      return;
    }
    if (p === '/api/rules' && req.method === 'POST') {
      const domain = String((body || {}).domain || '').trim().toLowerCase();
      const kind = (body || {}).kind;
      if (!domain) return json(res, 400, { error: 'invalid domain' });
      if (kind !== 'allow' && kind !== 'deny') return json(res, 400, { error: 'kind must be allow|deny' });
      const i = fixtures.rules.findIndex((r) => r.domain === domain);
      const entry = { domain, kind };
      if (i >= 0) fixtures.rules[i] = entry; else fixtures.rules.push(entry);
      fixtures.rules.sort((a, b) => a.domain.localeCompare(b.domain));
      return json(res, 200, { ok: true, domain, kind });
    }
    if (p === '/api/rules' && req.method === 'DELETE') {
      const domain = url.searchParams.get('domain');
      const i = fixtures.rules.findIndex((r) => r.domain === domain);
      if (i >= 0) fixtures.rules.splice(i, 1);
      return json(res, 200, { ok: true, existed: i >= 0 });
    }
    if (p === '/api/rules/bulk' && req.method === 'POST') {
      const lines = String((body || {}).domains || '').split(/[\r\n,]+/).filter(Boolean);
      const kind = (body || {}).kind;
      const valid = lines.map((l) => l.trim().toLowerCase()).filter(Boolean);
      for (const domain of valid) {
        const i = fixtures.rules.findIndex((r) => r.domain === domain);
        const entry = { domain, kind };
        if (i >= 0) fixtures.rules[i] = entry; else fixtures.rules.push(entry);
      }
      fixtures.rules.sort((a, b) => a.domain.localeCompare(b.domain));
      return json(res, 200, { ok: true, added: valid.length, skipped: [] });
    }

    // ---- probe ----
    if (p === '/api/test' && req.method === 'GET') {
      const domain = normalizeDomain(url.searchParams.get('domain') || '');
      if (!domain) return json(res, 400, { error: 'invalid domain' });
      const rule = fixtures.rules.find((r) => domain === r.domain || domain.endsWith('.' + r.domain));
      const keyword = fixtures.keywords.find((k) => domain.includes(k));
      const re = fixtures.regex.find((p) => { try { return new RegExp('^(?:' + p + ')$').test(domain); } catch { return false; } });
      const tld = domain.split('.').pop();
      let status = 'none', filter = null, matched = null;
      if (rule && rule.kind === 'deny') { status = 'deny'; filter = 'custom denylist'; matched = rule.domain; }
      else if (rule && rule.kind === 'allow') { status = 'allow'; filter = 'custom allowlist'; matched = rule.domain; }
      else if (fixtures.settings.tldBlock && fixtures.tlds.includes(tld)) { status = 'tld'; filter = 'blocked tlds'; matched = tld; }
      else if (fixtures.settings.keywordBlock && keyword) { status = 'keyword'; filter = 'blocked keywords'; matched = keyword; }
      else if (fixtures.settings.regexBlock && re) { status = 'regex'; filter = 'regex rules'; matched = re; }
      else if (domain.includes('.local') || domain.endsWith('.internal')) { status = 'rebind'; filter = 'rebinding'; matched = 'internal'; }
      const unicode = toUnicode(domain);
      return json(res, 200, {
        domain, unicode: unicode === domain ? null : unicode,
        status, filter, matched, blocklistSize: 184392,
        note: status === 'none' && fixtures.settings.rebindProtection
          ? 'answer-level rebinding check applies after upstream resolves' : null,
      });
    }

    // ---- settings ----
    if (p === '/api/settings') {
      if (req.method === 'GET') {
        return json(res, 200, {
          settings: fixtures.settings,
          upstream: resolveUpstream(fixtures.settings, {}),
          upstreamPresets: UPSTREAM_PRESETS,
        });
      }
      if (req.method === 'POST') {
        if (!body) return json(res, 400, { error: 'bad json' });
        Object.assign(fixtures.settings, body);
        return json(res, 200, {
          ok: true,
          settings: fixtures.settings,
          upstream: resolveUpstream(fixtures.settings, {}),
        });
      }
    }

    // ---- upstream connection test (hits the network from `vite dev`) ----
    if (p === '/api/upstream/test' && req.method === 'POST') {
      const preset = body && body.preset ? findPreset(body.preset) : undefined;
      if (body && body.preset && !preset) return json(res, 400, { error: 'unknown upstream provider' });
      /** @type {{url: string, kind: 'doh'|'odoh', relay?: string}} */
      let candidate;
      if (preset && preset.id === 'custom') {
        candidate = { url: String((body || {}).url || ''), kind: 'doh' };
      } else if (preset) {
        candidate = { url: preset.url, kind: preset.kind || 'doh', relay: String((body || {}).relay || '') };
      } else {
        candidate = {
          url: String((body || {}).url || ''),
          kind: (body || {}).kind === 'odoh' ? 'odoh' : 'doh',
          relay: String((body || {}).relay || ''),
        };
      }
      return json(res, 200, await probeUpstream(candidate));
    }

    // ---- response routes ----
    if (p === '/api/routes') {
      if (req.method === 'GET') return json(res, 200, { routes: fixtures.routes });
      if (req.method === 'POST') {
        const route = normalizeRoute(body);
        if (!route) return json(res, 400, { error: 'invalid route: needs a domain and an IPv4, IPv6 or hostname answer' });
        const i = fixtures.routes.findIndex((r) => r.domain === route.domain);
        if (i >= 0) fixtures.routes[i] = route; else fixtures.routes.push(route);
        fixtures.routes.sort((a, b) => a.domain.localeCompare(b.domain));
        return json(res, 200, { ok: true, route });
      }
      if (req.method === 'DELETE') {
        const domain = String(url.searchParams.get('domain') || '');
        const i = fixtures.routes.findIndex((r) => r.domain === domain);
        if (i >= 0) fixtures.routes.splice(i, 1);
        return json(res, 200, { ok: true, existed: i >= 0 });
      }
    }

    // ---- export / import ----
    if (p === '/api/export' && req.method === 'GET') {
      return json(res, 200, {
        version: 1,
        exportedAt: new Date().toISOString(),
        settings: fixtures.settings,
        rules: fixtures.rules,
        routes: fixtures.routes,
        keywords: fixtures.keywords,
        regex: fixtures.regex,
        tlds: fixtures.tlds,
      });
    }
    if (p === '/api/import' && req.method === 'POST') {
      const mode = body.mode === 'replace' ? 'replace' : 'merge';
      const summary = { mode, rules: null, routes: null, keywords: null, regex: null, tlds: null, settings: false };
      if (Array.isArray(body.routes)) {
        const valid = body.routes.map(normalizeRoute).filter(Boolean);
        if (mode === 'replace') fixtures.routes = valid.slice();
        else for (const r of valid) {
          const i = fixtures.routes.findIndex((x) => x.domain === r.domain);
          if (i >= 0) fixtures.routes[i] = r; else fixtures.routes.push(r);
        }
        fixtures.routes.sort((a, b) => a.domain.localeCompare(b.domain));
        summary.routes = { applied: valid.length, skipped: body.routes.length - valid.length };
      }
      if (Array.isArray(body.rules)) {
        if (mode === 'replace') fixtures.rules = body.rules.slice();
        else for (const r of body.rules) if (!fixtures.rules.some((x) => x.domain === r.domain)) fixtures.rules.push(r);
        fixtures.rules.sort((a, b) => a.domain.localeCompare(b.domain));
        summary.rules = { applied: body.rules.length, skipped: 0 };
      }
      if (Array.isArray(body.keywords)) {
        summary.keywords = mode === 'replace'
          ? (fixtures.keywords = body.keywords.slice(), body.keywords.length)
          : (body.keywords.forEach((k) => fixtures.keywords.includes(k) || fixtures.keywords.push(k)), body.keywords.length);
      }
      if (Array.isArray(body.regex)) {
        summary.regex = mode === 'replace'
          ? (fixtures.regex = body.regex.slice(), body.regex.length)
          : (body.regex.forEach((k) => fixtures.regex.includes(k) || fixtures.regex.push(k)), body.regex.length);
      }
      if (Array.isArray(body.tlds)) {
        summary.tlds = mode === 'replace'
          ? (fixtures.tlds = body.tlds.slice(), body.tlds.length)
          : (body.tlds.forEach((k) => fixtures.tlds.includes(k) || fixtures.tlds.push(k)), body.tlds.length);
      }
      if (body.settings) { Object.assign(fixtures.settings, body.settings); summary.settings = true; }
      return json(res, 200, { ok: true, ...summary });
    }

    // ---- filter lists ----
    const listMatch = p.match(/^\/api\/filters\/(keywords|tlds|regex)$/);
    if (listMatch) {
      const which = listMatch[1];
      const set = which === 'keywords' ? fixtures.keywords : which === 'regex' ? fixtures.regex : fixtures.tlds;
      const norm = which === 'keywords' ? normalizeKeyword : which === 'regex' ? normalizeRegex : normalizeTld;
      if (req.method === 'GET') return json(res, 200, { items: [...set].sort() });
      if (req.method === 'POST') {
        const v = norm((body || {}).value);
        if (!v) return json(res, 400, { error: 'invalid value' });
        const added = !set.includes(v);
        if (added) set.push(v);
        return json(res, 200, { ok: true, added, items: [...set].sort() });
      }
      if (req.method === 'DELETE') {
        const v = norm(url.searchParams.get('value'));
        const i = set.indexOf(v);
        if (i >= 0) set.splice(i, 1);
        return json(res, 200, { ok: true, removed: i >= 0, items: [...set].sort() });
      }
    }

    // ---- logs ----
    if (p === '/api/logs/stats' && req.method === 'GET') {
      const byStatus = new Map();
      for (const r of fixtures.logs) byStatus.set(r.status, (byStatus.get(r.status) || 0) + 1);
      const topMap = new Map();
      const clientMap = new Map();
      for (const r of fixtures.logs) {
        if (r.blocked) topMap.set(r.domain, (topMap.get(r.domain) || 0) + 1);
        if (r.client) clientMap.set(r.client, (clientMap.get(r.client) || 0) + 1);
      }
      const day = 24 * 3600 * 1000;
      const cutoff = Date.now() - 7 * day;
      const buckets = new Array(24).fill(0);
      for (const r of fixtures.logs) if (r.ts >= cutoff) buckets[new Date(Date.now() - (cutoff - r.ts)).getUTCHours()]++;
      return json(res, 200, {
        total: fixtures.logs.length,
        byStatus: { rows: [...byStatus].map(([status, n]) => ({ status, n })), total: fixtures.logs.length },
        topBlocked: [...topMap].map(([domain, n]) => ({ domain, n })).sort((a, b) => b.n - a.n).slice(0, 10),
        topClients: [...clientMap].map(([client, n]) => ({ client, n })).sort((a, b) => b.n - a.n).slice(0, 10),
        last24h: buckets,
      });
    }
    if (p === '/api/logs' && req.method === 'GET') {
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '100', 10) || 100, 500);
      const offset = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);
      const matches = logMatcher(url);
      let rows = fixtures.logs.filter(matches);
      const total = rows.length;
      rows = rows.slice(offset, offset + limit);
      return json(res, 200, { logs: rows.map(({ blocked, ...rest }) => rest), total });
    }
    if (p === '/api/logs' && req.method === 'DELETE') {
      const hasFilter = Boolean(url.searchParams.get('search') || url.searchParams.get('status')
        || url.searchParams.get('client') || url.searchParams.get('untagged') === '1');
      if (!hasFilter && url.searchParams.get('clear') !== '1') {
        return json(res, 400, { error: 'use ?clear=1 to delete all logs' });
      }
      fixtures.logs = fixtures.logs.filter((r) => !logMatcher(url)(r));
      return json(res, 200, { ok: true });
    }
    const one = p.match(/^\/api\/logs\/(\d+)$/);
    if (one && req.method === 'DELETE') {
      const id = Number(one[1]);
      fixtures.logs = fixtures.logs.filter((r) => r.id !== id);
      return json(res, 200, { ok: true });
    }

    json(res, 404, { error: 'not found' });
  };

  run().catch(() => json(res, 500, { error: 'mock failure' }));
}