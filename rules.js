// rules.js — Custom allow/deny rules, persisted in Workers KV as ONE blob.
//
// Storage layout (see lists.js for the rationale):
//   "rules:data"   -> newline-separated "kind<TAB>domain"   (the rules)
//   "data:version" -> timestamp bumped on any list write     (shared cache key)
//
// Legacy layout (one key per rule, no longer used for reads):
//   "rule:<domain>" -> "allow" | "deny"
// If "rules:data" is missing but legacy keys exist, they are migrated into the
// blob on first load. Legacy keys are left in place (deleting them would burn
// the free plan's 1,000 different-keys/day write quota) — see README for the
// one-time cleanup command.

import { DATA_VERSION_KEY, readSharedVersion, noteSharedVersion } from './lists.js';

const RULES_KEY = 'rules:data';
const LEGACY_PREFIX = 'rule:';
const CACHE_TTL_MS = 30_000;

/** @param {string} raw @returns {Map<string, 'allow'|'deny'>} */
function parseRules(raw) {
  const map = new Map();
  for (const line of raw.split('\n')) {
    const i = line.indexOf('\t');
    if (i === -1) continue;
    const kind = line.slice(0, i);
    const domain = line.slice(i + 1);
    if ((kind === 'allow' || kind === 'deny') && domain)   map.set(domain, kind);
  }
  return map;
}

export class RuleStore {
  /** @param {KVLike|null} kv */
  /** @param {KVLike} kv (start null; call bind() once the binding is known) */
  constructor(kv) {
    this.kv = kv;
    /** @type {Map<string, 'allow'|'deny'>} */
    this.rules = new Map(); // domain -> 'allow' | 'deny'
    /** @type {string|null} */
    this.version = null;
    this.loaded = false;
    this.cachedAt = 0;
  }

  /**
   * Point the store at a different KV binding and drop all in-memory state.
   * A binding change means a *different namespace* — keeping the TTL cache
   * would serve another namespace's rules for up to CACHE_TTL.
   */
  /** @param {KVLike} kv */
  bind(kv) {
    this.kv = kv;
    this.rules = new Map();
    this.version = null;
    this.loaded = false;
    this.cachedAt = 0;
  }

  /**
   * Cheap while cached (no I/O). force skips the version check.
   *
   * Failure handling: any KV read error keeps the current in-memory rules and
   * just re-throttles the TTL. We never substitute an empty set for a failed
   * read, and we only commit `this.version` after a *successful* load —
   * otherwise a transient error could be mistaken for "already current" or
   * (worse) trigger a migration that persists an empty blob over real data.
   */
  async refresh(force = false) {
    const now = Date.now();
    // Guard on cachedAt, not `loaded`, so a failed load throttles retries too.
    if (!force && this.cachedAt && now - this.cachedAt < CACHE_TTL_MS) return;

    /** @type {string|null} null = shared version read failed */
    const version = await readSharedVersion(this.kv, force);
    if (version === null) {
      this.cachedAt = Date.now(); // keep stale; retry after TTL
      return;
    }
    if (!force && this.version !== null && version === this.version) {
      this.cachedAt = Date.now();
      return;
    }

    let raw;
    let readOk = false;
    try { raw = await this.kv.get(RULES_KEY, 'text'); readOk = true; } catch { /* stale read: retry after TTL */ }
    if (!readOk) {
      this.cachedAt = Date.now(); // keep stale; retry after TTL
      return;
    }

    if (raw === null || raw === undefined) {
      // Read succeeded and the key is genuinely absent -> maybe legacy layout.
      const migrated = await this.migrateLegacy();
      if (migrated === null) {
        this.cachedAt = Date.now(); // scan failed; keep stale
        return;
      }
    } else {
      this.rules = parseRules(raw);
    }

    this.version = version; // only after a successful load
    this.loaded = true;
    this.cachedAt = Date.now();
  }

  /**
   * One-time import of the old one-key-per-rule layout.
   * @returns {Promise<Map<string, 'allow'|'deny'>|null>} the migrated map, or null if the scan failed
   *   (null tells the caller to keep its current data rather than trust an
   *   empty result).
   */
  async migrateLegacy() {
    const map = new Map();
    let scanOk;
    try {
      let cursor;
      do {
        const page = await this.kv.list({ prefix: LEGACY_PREFIX, cursor });
        cursor = page.list_complete ? undefined : page.cursor;
        const keys = page.keys.map((k) => k.name);
        for (let i = 0; i < keys.length; i += 20) {
          const batch = keys.slice(i, i + 20);
          const values = await Promise.all(batch.map((k) => this.kv.get(k, 'text')));
          for (let j = 0; j < batch.length; j++) {
            const kind = values[j];
            if (kind === 'allow' || kind === 'deny') {
              map.set(batch[j].slice(LEGACY_PREFIX.length), kind);
            }
          }
        }
      } while (cursor);
      scanOk = true;
    } catch { /* list scan failed: map is discarded via !scanOk */ }

    // Scan failed -> indistinguishable from "no legacy keys"; don't write.
    if (!scanOk) return null;

    this.rules = map;
    // Scan succeeded, so an empty result really means "fresh install".
    // Persist so the scan never runs again.
    try { await this.save(); } catch { /* next refresh retries */ }
    return map;
  }

  /**
   * Returns the winning rule: { kind, at } where `at` is the rule that matched
   * (may be a parent of `domain`). Allow wins across all parent levels;
   * otherwise the most specific deny wins.
   */
  /** @param {string} domain @returns {{kind:'allow'|'deny', at:string}|null} */
  match(domain) {
    const map = this.rules;
    if (map.size === 0) return null;

    let d = domain;
    if (d.charCodeAt(d.length - 1) === 46) d = d.slice(0, -1);

    /** @type {{kind:'allow'|'deny', at:string}|null} */
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

  /** @param {string} domain @returns {'allow'|'deny'|null} */
  lookup(domain) {
    const m = this.match(domain);
    return m ? m.kind : null;
  }

  /** @param {string} domain @param {'allow'|'deny'} kind */
  async put(domain, kind) {
    const d = normalizeDomain(domain);
    if (!d) throw new Error('invalid domain');
    if (kind !== 'allow' && kind !== 'deny') throw new Error('invalid kind');

    await this.refresh(true);
    this.rules.set(d, kind);
    await this.save();
  }

  /**
   * Bulk add in ONE read + ONE write (instead of N of each).
   * @param {Array<{domain?: unknown, kind?: unknown}>} entries
   * @returns {Promise<number>} count actually applied
   */
  async putBulk(entries) {
    await this.refresh(true);
    let n = 0;
    for (const e of entries) {
      const d = normalizeDomain(e.domain);
      if (!d || (e.kind !== 'allow' && e.kind !== 'deny')) continue;
      if (this.rules.get(d) !== e.kind) n++;
      this.rules.set(d, e.kind);
    }
    if (n) await this.save();
    return n;
  }

  /**
   * Swap the entire rule map for `entries` in ONE read + ONE save.
   * Used by config import in replace mode.
   * @param {Array<{domain?: unknown, kind?: unknown}>} entries
   * @returns {Promise<number>} total rules kept after the swap
   */
  async replaceAll(entries) {
    const map = new Map();
    for (const e of entries) {
      const d = normalizeDomain(e.domain);
      if (!d || (e.kind !== 'allow' && e.kind !== 'deny')) continue;
      map.set(d, e.kind);
    }
    await this.refresh(true);
    this.rules = map;
    await this.save();
    return map.size;
  }

  /** @param {string} domain @returns {Promise<boolean>} */
  async delete(domain) {
    const d = normalizeDomain(domain);
    if (!d) return false;
    await this.refresh(true);
    if (!this.rules.delete(d)) return false;
    await this.save();
    return true;
  }

  /** @returns {Promise<Array<{domain:string, kind:'allow'|'deny'}>>} */
  async list() {
    const out = [];
    for (const [domain, kind] of this.rules) out.push({ domain, kind });
    out.sort((a, b) => a.domain.localeCompare(b.domain));
    return out;
  }

  async save() {
    const lines = [];
    for (const [domain, kind] of this.rules) lines.push(kind + '\t' + domain);
    await this.kv.put(RULES_KEY, lines.join('\n'));
    const v = String(Date.now());
    await this.kv.put(DATA_VERSION_KEY, v);
    this.version = v;
    noteSharedVersion(this.kv, v);
    this.cachedAt = Date.now();
  }
}

/** @param {unknown} raw @returns {string} */
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
