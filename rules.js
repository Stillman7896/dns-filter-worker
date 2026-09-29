const VERSION_KEY = 'rules:version';
const CACHE_TTL_MS = 30_000; // how long an isolate trusts its cached rules
const KEY_PREFIX = 'rule:';

export class RuleStore {
  constructor(kv) {
    this.kv = kv;
    this.cache = new Map(); // domain -> 'allow'|'deny'
    this.cachedVersion = null;
    this.cachedAt = 0;
  }

  async refresh(force = false) {
    const now = Date.now();
    if (!force && this.cachedAt && now - this.cachedAt < CACHE_TTL_MS) return;

    let version;
    try {
      version = (await this.kv.get(VERSION_KEY)) || '0';
    } catch {
      this.cachedAt = now; // keep serving stale rather than fail closed
      return;
    }

    if (!force && version === this.cachedVersion) {
      this.cachedAt = now;
      return;
    }

    const map = new Map();
    let cursor;
    do {
      const page = await this.kv.list({ prefix: KEY_PREFIX, cursor });
      cursor = page.list_complete ? undefined : page.cursor;

      const keys = page.keys.map((k) => k.name);
      const CONC = 20;
      for (let i = 0; i < keys.length; i += CONC) {
        const batch = keys.slice(i, i + CONC);
        const values = await Promise.all(batch.map((k) => this.kv.get(k, 'text')));
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
   * Returns the winning rule for a domain: { kind, at } where `at` is the
   * rule that matched (may be a parent of `domain`).
   *
   * Allow wins globally across all parent levels; otherwise the most specific
   * deny wins.
   * @param {string} domain
   * @returns {{kind:'allow'|'deny', at:string}|null}
   */
  match(domain) {
    const map = this.cache;
    if (map.size === 0) return null;

    let d = domain;
    if (d.charCodeAt(d.length - 1) === 46) d = d.slice(0, -1);

    let denyHit = null;
    for (;;) {
      const hit = map.get(d);
      if (hit === 'allow') return { kind: 'allow', at: d };
      if (hit === 'deny' && denyHit === null) denyHit = { kind: 'deny', at: d };

      const dot = d.indexOf('.');
      if (dot === -1) break;
      d = d.slice(dot + 1);
      if (d.indexOf('.') === -1) {
        const last = map.get(d);
        if (last === 'allow') return { kind: 'allow', at: d };
        if (last === 'deny' && denyHit === null) denyHit = { kind: 'deny', at: d };
        break;
      }
    }

    return denyHit;
  }

  /**
   * @param {string} domain
   * @returns {'allow'|'deny'|null}
   */
  lookup(domain) {
    const m = this.match(domain);
    return m ? m.kind : null;
  }

  async put(domain, kind) {
    const d = normalizeDomain(domain);
    if (!d) throw new Error('invalid domain');
    if (kind !== 'allow' && kind !== 'deny') throw new Error('invalid kind');

    await this.kv.put(KEY_PREFIX + d, kind);
    await this.kv.put(VERSION_KEY, String(Date.now()));
    this.cachedVersion = null;
  }

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

  async list() {
    const out = [];
    for (const [domain, kind] of this.cache) out.push({ domain, kind });
    out.sort((a, b) => a.domain.localeCompare(b.domain));
    return out;
  }
}

export function normalizeDomain(raw) {
  if (typeof raw !== 'string') return '';
  let s = raw.trim().toLowerCase();
  if (!s) return '';

  s = s.replace(/^[a-z]+:\/\//, '');
  const slash = s.indexOf('/');
  if (slash !== -1) s = s.slice(0, slash);

  const colon = s.lastIndexOf(':');
  if (colon !== -1 && /^\d+$/.test(s.slice(colon + 1))) s = s.slice(0, colon);

  if (s.startsWith('*.')) s = s.slice(2);
  else if (s.startsWith('.')) s = s.slice(1);

  if (s.endsWith('.')) s = s.slice(0, -1);

  if (s.length < 3 || s.length > 253) return '';
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(s)) {
    return '';
  }
  return s;
}
