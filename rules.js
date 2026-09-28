
// Storage layout:
//   key   = "rule:<domain>"
//   value = "allow" | "deny"
//
// We keep an in-isolate cache so hot lookups don't hit KV on every query.
// The cache is invalidated by bumping a version key that every isolate
// re-checks at most once per CACHE_TTL_MS.

const VERSION_KEY = 'rules:version';
const CACHE_TTL_MS = 30_000; // how long an isolate trusts its cached rules
const KEY_PREFIX = 'rule:';

export class RuleStore {
  constructor(kv) {
    this.kv = kv;

    /** @type {Map<string, 'allow'|'deny'>} */
    this.cache = new Map();
    this.cachedVersion = null;
    this.cachedAt = 0;
  }

  /** Refresh rules from KV if the version changed or TTL expired. */
  async refresh(force = false) {
    const now = Date.now();
    if (!force && this.cachedAt && now - this.cachedAt < CACHE_TTL_MS) {
      return;
    }

    let version;
    try {
      version = (await this.kv.get(VERSION_KEY)) || '0';
    } catch {
      // KV unavailable — keep serving from stale cache rather than fail closed.
      this.cachedAt = now;
      return;
    }

    if (!force && version === this.cachedVersion) {
      this.cachedAt = now;
      return;
    }

    // List all rules. Hagezi-scale custom rules are user-curated and small
    // (thousands at most), so a single list() is fine.
    const map = new Map();
    let cursor;
    do {
      const page = await this.kv.list({ prefix: KEY_PREFIX, cursor });
      cursor = page.list_complete ? undefined : page.cursor;

      const keys = page.keys.map((k) => k.name);
      // KV doesn't support multi-get; fan out. Cap concurrency to be polite.
      const CONC = 20;
      for (let i = 0; i < keys.length; i += CONC) {
        const batch = keys.slice(i, i + CONC);
        const values = await Promise.all(
          batch.map((k) => this.kv.get(k, 'text'))
        );
        for (let j = 0; j < batch.length; j++) {
          const v = values[j];
          if (v === 'allow' || v === 'deny') {
            map.set(batch[j].slice(KEY_PREFIX.length), v);
          }
        }
      }
    } while (cursor);

    this.cache = map;
    this.cachedVersion = version;
    this.cachedAt = now;
  }

  /**
   * Returns 'allow' | 'deny' | null for a domain, using subdomain-walk
   * precedence so `example.com` in the allowlist also allows `a.example.com`.
   *
   * Allow is checked first across all parents; if any parent is allowed,
   * the request is allowed. Otherwise the *most specific* deny wins.
   */
  lookup(domain) {
    const map = this.cache;
    if (map.size === 0) return null;

    let d = domain;
    if (d.charCodeAt(d.length - 1) === 46) d = d.slice(0, -1);

    // Walk labels, check allow first at every level (allow wins globally),
    // and remember the first deny we hit (most specific deny).
    let denyHit = null;
    for (;;) {
      const hit = map.get(d);
      if (hit === 'allow') return 'allow';
      if (hit === 'deny' && denyHit === null) denyHit = 'deny';

      const dot = d.indexOf('.');
      if (dot === -1) break;
      d = d.slice(dot + 1);
      if (d.indexOf('.') === -1) {
        const last = map.get(d);
        if (last === 'allow') return 'allow';
        if (last === 'deny' && denyHit === null) denyHit = 'deny';
        break;
      }
    }

    return denyHit;
  }

  /** Add or replace a rule. kind = 'allow' | 'deny'. */
  async put(domain, kind) {
    const d = normalizeDomain(domain);
    if (!d) throw new Error('invalid domain');
    if (kind !== 'allow' && kind !== 'deny') throw new Error('invalid kind');

    await this.kv.put(KEY_PREFIX + d, kind);
    await this.kv.put(VERSION_KEY, String(Date.now()));
    this.cachedVersion = null; // force refresh next lookup
  }

  /** Delete a rule. Returns true if it existed. */
  async delete(domain) {
    const d = normalizeDomain(domain);
    if (!d) throw new Error('invalid domain');
    const existing = await this.kv.get(KEY_PREFIX + d);
    if (existing == null) return false;
    await this.kv.delete(KEY_PREFIX + d);
    await this.kv.put(VERSION_KEY, String(Date.now()));
    this.cachedVersion = null;
    return true;
  }

  /** List all rules for the dashboard. */
  async list() {
    const out = [];
    const map = this.cache;
    for (const [domain, kind] of map) out.push({ domain, kind });
    out.sort((a, b) => a.domain.localeCompare(b.domain));
    return out;
  }
}

/**
 * Normalize a user-entered domain: strip scheme, path, leading `*.`,
 * lowercase, strip trailing dot. Returns '' if invalid.
 */
export function normalizeDomain(raw) {
  if (typeof raw !== 'string') return '';
  let s = raw.trim().toLowerCase();
  if (!s) return '';

  // Strip scheme + path
  s = s.replace(/^[a-z]+:\/\//, '');
  const slash = s.indexOf('/');
  if (slash !== -1) s = s.slice(0, slash);

  // Strip port
  const colon = s.lastIndexOf(':');
  if (colon !== -1 && /^\d+$/.test(s.slice(colon + 1))) s = s.slice(0, colon);

  // Strip leading wildcard / leading dot
  if (s.startsWith('*.')) s = s.slice(2);
  else if (s.startsWith('.')) s = s.slice(1);

  if (s.endsWith('.')) s = s.slice(0, -1);

  // Basic validation: at least one dot, labels 1..63, total ≤ 253
  if (s.length < 3 || s.length > 253) return '';
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(s)) {
    return '';
  }
  return s;
}
