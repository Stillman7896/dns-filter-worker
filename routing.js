// routing.js — per-domain answer overrides ("response routing"), KV-backed.
//
// A route answers a name (and every subdomain of it) with a fixed record
// instead of asking an upstream: an IPv4/IPv6 literal, or a CNAME pointing at
// another name. Local names and private addresses are allowed here — that is
// the point of the feature — and routes are checked before every other filter.
//
// Storage layout (see lists.js for why one blob, not one key per route):
//   "routes:data"  -> newline "domain<TAB>type<TAB>value<TAB>ttl"
//   "data:version" -> shared timestamp bumped on any list write

import { DATA_VERSION_KEY, readSharedVersion, noteSharedVersion } from './lists.js';
import { normalizeDomain } from './rules.js';
import { RR, parseIpv4, parseIpv6, encodeName } from './dns.js';

export const ROUTES_KEY = 'routes:data';
const CACHE_TTL_MS = 30_000;
export const DEFAULT_ROUTE_TTL = 300;
export const MAX_ROUTE_TTL = 86_400;

/** @typedef {'a'|'aaaa'|'cname'} RouteType */
/** @typedef {{domain: string, type: RouteType, value: string, ttl: number}} Route */

/** Record type implied by a value: an IP literal, or a hostname to alias.
 * @param {unknown} raw @returns {{type: RouteType, value: string}|null}
 */
export function normalizeRouteValue(raw) {
  if (typeof raw !== 'string') return null;
  const value = raw.trim().toLowerCase().replace(/\.$/, '');
  if (!value) return null;

  const v4 = parseIpv4(value);
  if (v4) return { type: 'a', value: [...v4].join('.') };

  // Anything made only of digits and dots must be a real IPv4 literal: a
  // malformed one is a typo, not a hostname to alias.
  if (/^[\d.]+$/.test(value)) return null;

  if (parseIpv6(value)) return { type: 'aaaa', value };

  const domain = normalizeDomain(value);
  return domain ? { type: 'cname', value: domain } : null;
}

/** @param {unknown} raw @param {number} [max] @returns {number} */
export function clampTtl(raw, max = MAX_ROUTE_TTL) {
  if (typeof raw !== 'number' || !Number.isFinite(raw)) return DEFAULT_ROUTE_TTL;
  return Math.min(max, Math.max(0, Math.floor(raw)));
}

/**
 * Validate one route from user input or an imported config.
 * @param {unknown} input
 * @returns {Route|null}
 */
export function normalizeRoute(input) {
  if (!input || typeof input !== 'object') return null;
  const src = /** @type {Record<string, unknown>} */ (input);
  const domain = normalizeDomain(src.domain);
  if (!domain) return null;
  const inferred = normalizeRouteValue(src.value ?? src.target);
  if (!inferred) return null;
  const asked = src.type;
  // An explicit type that contradicts the value (e.g. "a" + hostname) is
  // rejected: the record has to match the value to stay encodable.
  if ((asked === 'a' || asked === 'aaaa' || asked === 'cname') && asked !== inferred.type) return null;
  return {
    domain,
    type: inferred.type,
    value: inferred.value,
    ttl: clampTtl(typeof src.ttl === 'number' ? src.ttl : NaN),
  };
}

/** @param {Route} route @returns {string} */
export function formatRouteLine(route) {
  return [route.domain, route.type, route.value, route.ttl].join('\t');
}

/** @param {string} line @returns {Route|null} */
export function parseRouteLine(line) {
  const [domain, type, value, ttl] = line.split('\t');
  return normalizeRoute({ domain, type, value, ttl: Number(ttl) });
}

export class RouteStore {
  /** @param {KVLike} kv (start null; call bind() once the binding is known) */
  constructor(kv) {
    this.kv = kv;
    /** @type {Map<string, Route>} */
    this.routes = new Map();
    /** @type {string|null} */
    this.version = null;
    this.loaded = false;
    this.cachedAt = 0;
  }

  /** Point at a different KV binding and drop cached data (see rules.js). */
  /** @param {KVLike} kv */
  bind(kv) {
    this.kv = kv;
    this.routes = new Map();
    this.version = null;
    this.loaded = false;
    this.cachedAt = 0;
  }

  /**
   * Cheap while cached (no I/O). A failed read keeps the current routes and
   * only re-throttles the TTL — never substitute an empty set (see rules.js).
   * @param {boolean} [force]
   * @returns {Promise<void>}
   */
  async refresh(force = false) {
    const now = Date.now();
    if (!force && this.cachedAt && now - this.cachedAt < CACHE_TTL_MS) return;

    /** @type {string|null} null = version read failed */
    const version = await readSharedVersion(this.kv, force);
    if (version === null) {
      this.cachedAt = now;
      return;
    }
    if (!force && this.version !== null && version === this.version) {
      this.cachedAt = Date.now();
      return;
    }

    let raw;
    try { raw = await this.kv.get(ROUTES_KEY, 'text'); } catch { this.cachedAt = now; return; }

    const routes = new Map();
    if (raw) {
      for (const line of raw.split('\n')) {
        if (!line) continue;
        const route = parseRouteLine(line);
        if (route) routes.set(route.domain, route);
      }
    }
    this.routes = routes;
    this.version = version; // only after a successful load
    this.loaded = true;
    this.cachedAt = Date.now();
  }

  /** @returns {Route[]} */
  list() {
    return [...this.routes.values()].sort((a, b) => a.domain.localeCompare(b.domain));
  }

  /**
   * Most specific route for `name` or one of its parents, or null.
   * @param {string} name @returns {(Route & {at: string})|null}
   */
  match(name) {
    if (this.routes.size === 0) return null;
    let d = name.replace(/\.$/, '');
    for (;;) {
      const hit = this.routes.get(d);
      if (hit) return { ...hit, at: d };
      const dot = d.indexOf('.');
      if (dot === -1) return null;
      d = d.slice(dot + 1);
      if (d.indexOf('.') === -1) {
        const last = this.routes.get(d);
        return last ? { ...last, at: d } : null;
      }
    }
  }

  /**
   * Create or replace one route.
   * @param {unknown} input
   * @returns {Promise<Route>}
   */
  async put(input) {
    const route = normalizeRoute(input);
    if (!route) throw new Error('invalid route');
    await this.refresh(true);
    this.routes.set(route.domain, route);
    await this.save();
    return route;
  }

  /** @param {string} domain @returns {Promise<boolean>} true if one was removed */
  async delete(domain) {
    const d = normalizeDomain(domain);
    if (!d) return false;
    await this.refresh(true);
    if (!this.routes.delete(d)) return false;
    await this.save();
    return true;
  }

  /**
   * Swap every route for `entries` (config import, replace mode).
   * @param {unknown[]} entries
   * @returns {Promise<{applied: number, skipped: number}>}
   */
  async replaceAll(entries) {
    const next = new Map();
    let skipped = 0;
    for (const e of entries) {
      const route = normalizeRoute(e);
      if (!route) { skipped++; continue; }
      next.set(route.domain, route);
    }
    await this.refresh(true);
    this.routes = next;
    await this.save();
    return { applied: next.size, skipped };
  }

  /**
   * Merge `entries` in (config import, merge mode).
   * @param {unknown[]} entries
   * @returns {Promise<{applied: number, skipped: number}>}
   */
  async addMany(entries) {
    await this.refresh(true);
    let applied = 0, skipped = 0;
    for (const e of entries) {
      const route = normalizeRoute(e);
      if (!route) { skipped++; continue; }
      applied++;
      this.routes.set(route.domain, route);
    }
    if (applied) await this.save();
    return { applied, skipped };
  }

  /** @returns {Promise<void>} */
  async save() {
    const lines = [];
    for (const r of this.list()) lines.push(formatRouteLine(r));
    await this.kv.put(ROUTES_KEY, lines.join('\n'));
    const v = String(Date.now());
    await this.kv.put(DATA_VERSION_KEY, v);
    this.version = v;
    noteSharedVersion(this.kv, v);
    this.cachedAt = Date.now();
  }
}

/**
 * Answer records for a route. Types the route does not cover come back empty
 * (NODATA) so an overridden name never leaks to the upstream.
 * @param {Pick<Route, 'type'|'value'|'ttl'>} route
 * @param {string} qname
 * @param {number} qtype
 * @returns {Array<{name: string, type: number, rdata: Uint8Array, ttl: number}>}
 */
export function routeRecords(route, qname, qtype) {
  const ttl = route.ttl;
  if (route.type === 'cname') {
    return [{ name: qname, type: RR.CNAME, rdata: encodeName(route.value), ttl }];
  }
  if (route.type === 'a' && qtype === RR.A) {
    const rdata = parseIpv4(route.value);
    return rdata ? [{ name: qname, type: RR.A, rdata, ttl }] : [];
  }
  if (route.type === 'aaaa' && qtype === RR.AAAA) {
    const rdata = parseIpv6(route.value);
    return rdata ? [{ name: qname, type: RR.AAAA, rdata, ttl }] : [];
  }
  return [];
}
