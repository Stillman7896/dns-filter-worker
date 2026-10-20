// lists.js — Newline-delimited string sets persisted as a single KV blob.
//
// WHY A BLOB INSTEAD OF ONE KEY PER ENTRY
// ----------------------------------------
// Cloudflare KV has *unlimited* keys per namespace, so key count is never the
// issue. The binding limits are:
//   • 1,000 KV operations per Worker invocation  — a `list()` + N `get()` for
//     N rules blows past this once N is in the thousands.
//   • 1,000 writes to *different* keys per day on the free plan.
// Storing each list as ONE value means a refresh costs 1 version read (+ 1 blob
// read only when something changed), and a write costs 2 writes total.
//
// SHARED VERSION KEY
// ------------------
// Every KV-backed store bumps the same `data:version` key on write, so a single
// tiny read per cache TTL tells *all* stores whether to re-read their blob.

const CACHE_TTL_MS = 30_000;

export const DATA_VERSION_KEY = 'data:version';

// ---- Shared version read ----------------------------------------------------
// Every blob store watches the same `data:version` key, so the read is shared
// per KV binding: N stores cost ONE KV read per window instead of N. Keyed by
// the binding object, so a namespace switch (or the test doubles) never see
// another namespace's version.

/** @type {WeakMap<object, {value: string|null, at: number, inflight: Promise<string|null>|null}>} */
const versionCache = new WeakMap();

/**
 * @param {KVLike} kv
 * @param {{value: string|null, at: number, inflight: Promise<string|null>|null}} entry
 * @returns {Promise<string|null>} null = read failed (caller keeps stale data)
 */
function readVersion(kv, entry) {
  entry.inflight = (async () => {
    try {
      const v = (await kv.get(DATA_VERSION_KEY)) || '0';
      entry.value = v;
      return v;
    } catch {
      return null; // keep entry.value for later; retry after the TTL window
    } finally {
      entry.at = Date.now();
      entry.inflight = null;
    }
  })();
  return entry.inflight;
}

/**
 * Current `data:version` for a binding, cached for CACHE_TTL_MS and
 * de-duplicated across concurrent callers. force=true always reads fresh
 * (writes need the latest version, bypassing the window).
 * @param {KVLike} kv
 * @param {boolean} [force]
 * @returns {Promise<string|null>}
 */
export function readSharedVersion(kv, force = false) {
  // Unbound store (no KV binding yet): treat as a failed read so callers keep
  // their in-memory state instead of throwing on a null WeakMap key.
  if (kv === null || (typeof kv !== 'object' && typeof kv !== 'function')) return Promise.resolve(null);
  let e = versionCache.get(kv);
  if (!e) {
    e = { value: null, at: 0, inflight: null };
    versionCache.set(kv, e);
  }
  if (force) return readVersion(kv, e);
  if (e.inflight) return e.inflight;
  if (e.value !== null && Date.now() - e.at < CACHE_TTL_MS) return Promise.resolve(e.value);
  return readVersion(kv, e);
}

/**
 * Record a version this isolate just wrote, so every store on the binding
 * picks it up immediately instead of waiting out the window.
 * @param {KVLike} kv
 * @param {string} v
 */
export function noteSharedVersion(kv, v) {
  if (kv === null || (typeof kv !== 'object' && typeof kv !== 'function')) return;
  versionCache.set(kv, { value: v, at: Date.now(), inflight: null });
}

/** Trim + lowercase; returns '' for anything unusable.
 * @param {unknown} raw
 * @returns {string}
 */
export function normalizeEntry(raw) {
  if (typeof raw !== 'string') return '';
  return raw.trim().toLowerCase().replace(/^[-.*]+/, '').replace(/\.+$/, '');
}

/** TLD normalization: strip leading dot, require a single label. */
/** @param {unknown} raw @returns {string} */
export function normalizeTld(raw) {
  const s = normalizeEntry(raw);
  if (!s || s.length < 2 || s.length > 63) return '';
  if (s.includes('.') || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(s)) return '';
  return s;
}

/**
 * Keyword validation: the entry is stored and matched verbatim — no trimming,
 * no wildcard/dot/dash stripping. Query names arrive lowercase (parseQuestion),
 * so anything else could never match and is rejected instead: lowercase
 * letters, digits, dash and dot, 4–64 characters.
 * @param {unknown} raw @returns {string}
 */
export function normalizeKeyword(raw) {
  if (typeof raw !== 'string') return '';
  return /^[a-z0-9.-]{4,64}$/.test(raw) ? raw : '';
}

export class TextSetStore {
  /**
   * `validate` normalizes/validates every entry (add, remove, blob load).
   * Defaults to the permissive domain-entry normalizer; stricter callers pass
   * e.g. normalizeKeyword.
   * @param {KVLike} kv @param {string} key @param {(raw:unknown)=>string} [validate]
   */
  constructor(kv, key, validate = normalizeEntry) {
    this.kv = kv;
    this.key = key;
    this.validate = validate;
    this.set = new Set();
    /** @type {string|null} */
    this.version = null;
    this.loaded = false;
    this.cachedAt = 0;
  }

  /** Point at a different KV binding and drop cached data (see rules.js). */
  /** @param {KVLike} kv */
  bind(kv) {
    this.kv = kv;
    this.set = new Set();
    this.version = null;
    this.loaded = false;
    this.cachedAt = 0;
  }

  /**
   * Cheap while cached (no I/O). force skips the version equality check.
   *
   * Failure handling mirrors rules.js: any KV read error keeps the current
   * set and just re-throttles the TTL. Never substitute an empty set for a
   * failed read — `add()`/`remove()` do read-modify-write, so a silent wipe
   * would get persisted on the next save.
   */
  async refresh(force = false) {
      const now = Date.now();
      if (!force && this.cachedAt && now - this.cachedAt < CACHE_TTL_MS) return;

      /** @type {string|null} null = version read failed */
    const version = await readSharedVersion(this.kv, force);
      if (version === null) {
        this.cachedAt = now; // version read failed: keep stale; retry after TTL
        return;
      }
      if (!force && this.version !== null && version === this.version) {
        this.cachedAt = Date.now();
        return;
      }

    let raw;
    let readOk = false;
    try { raw = await this.kv.get(this.key, 'text'); readOk = true; } catch { /* stale read: retry after TTL */ }
    if (!readOk) {
      this.cachedAt = now; // keep stale; retry after TTL
      return;
    }

    const set = new Set();
    if (raw) {
      for (const line of raw.split('\n')) {
        const v = this.validate(line);
        if (v) set.add(v);
      }
    }
    this.set = set;
    this.version = version; // only after a successful load
    this.loaded = true;
    this.cachedAt = Date.now();
  }

  /** @returns {Set<string>} */
  get() { return this.set; }
  /** @returns {string[]} */
  list() { return [...this.set].sort(); }

  /** @returns {Promise<boolean>} true if newly added */
  /** @param {unknown} value @returns {Promise<boolean>} true if newly added */
  async add(value) {
    const v = this.validate(value);
    if (!v) throw new Error('invalid entry');
    await this.refresh(true); // read-modify-write from fresh state
    if (this.set.has(v)) return false;
    this.set.add(v);
    await this.save();
    return true;
  }

  /** @returns {Promise<boolean>} true if it existed and was removed */
  /** @param {unknown} value @returns {Promise<boolean>} true if it existed and was removed */
  async remove(value) {
    const v = this.validate(value);
    if (!v) return false;
    await this.refresh(true);
    if (!this.set.delete(v)) return false;
    await this.save();
    return true;
  }

  /**
   * Add many entries in ONE read-modify-write (config import, merge mode).
   * @param {string[]} values
   * @param {(raw:unknown)=>string} [validate] normalizer; invalid entries skipped
   * @returns {Promise<{applied:number, skipped:number}>}
   */
  async addMany(values, validate = this.validate) {
    await this.refresh(true);
    let applied = 0, skipped = 0;
    for (const v of values) {
      if (typeof v !== 'string' || !v.trim()) { skipped++; continue; }
      const n = validate(v);
      if (!n) { skipped++; continue; }
      if (!this.set.has(n)) { this.set.add(n); applied++; }
    }
    if (applied) await this.save();
    return { applied, skipped };
  }

  /**
   * Swap the whole set for `values` in ONE read + ONE save
   * (config import, replace mode).
   * @returns {Promise<{applied:number, skipped:number}>}
   */
  /**
   * @param {unknown[]} values
   * @param {(raw:unknown)=>string} [validate]
   * @returns {Promise<{applied:number, skipped:number}>}
   */
  async replaceAll(values, validate = this.validate) {
    const next = new Set();
    let skipped = 0;
    for (const v of values) {
      if (typeof v !== 'string' || !v.trim()) { skipped++; continue; }
      const n = validate(v);
      if (!n) { skipped++; continue; }
      next.add(n);
    }
    await this.refresh(true);
    this.set = next;
    await this.save();
    return { applied: next.size, skipped };
  }

  /** @returns {Promise<void>} */
  async save() {
    await this.kv.put(this.key, this.list().join('\n'));
    const v = String(Date.now());
    await this.kv.put(DATA_VERSION_KEY, v);
    this.version = v;
    noteSharedVersion(this.kv, v);
    this.cachedAt = Date.now();
  }
}
