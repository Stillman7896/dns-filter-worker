// settings.js — Persistent filter settings in Workers KV.
//
// Storage: single JSON blob at key "settings:main" in the same KV namespace
// as the rules. Hot-path reads are zero-I/O: an isolate loads once, caches,
// and only re-reads KV after CACHE_TTL. Dashboard writes update this
// isolate immediately and others pick up the change within CACHE_TTL.
//
// Failure handling: a *successful* read of an absent key falls back to
// DEFAULT_SETTINGS (fresh install); a *failed* read keeps the current cache so
// a transient error can't silently reset the user's toggles.

export const SETTINGS_KEY = 'settings:main';
export const CACHE_TTL_MS = 30_000;

/** @type {FilterSettings} */
export const DEFAULT_SETTINGS = Object.freeze({
  rebindProtection: true, // block private/internal IPs in answers + internal hostnames
  idnBlock: false,        // block all punycode / non-ASCII labels (homograph defense)
  tldBlock: false,        // block queries whose TLD is in the Blocked-TLD list
  keywordBlock: false,    // block queries containing any Blocked-keyword
  logPassed: true,        // write allow/none rows to dns_logs; false = blocks only
  logRetentionDays: 30,   // delete dns_logs rows older than this; 0 = keep forever
});

/** Clamp a candidate retention value; returns 0..3650 or NaN if not a number.
 * @param {unknown} v
 * @returns {number}
 */
export function clampRetention(v) {
  if (typeof v !== 'number' || !Number.isFinite(v)) return NaN;
  return Math.min(3650, Math.max(0, Math.floor(v)));
}

export class SettingsStore {
  /** @param {KVLike} kv */
  constructor(kv) {
    this.kv = kv;
    this.cache = { ...DEFAULT_SETTINGS };
    this.loaded = false;
    this.cachedAt = 0;
    this.loading = null;
  }

  /**
   * Point at a different KV binding and reset to defaults until the next
   * successful load (see rules.js for the rationale).
   */
  /** @param {KVLike} kv */
  bind(kv) {
    this.kv = kv;
    this.cache = { ...DEFAULT_SETTINGS };
    this.loaded = false;
    this.cachedAt = 0;
  }

  /**
   * Ensure settings are loaded. Cheap no-op while cached (no I/O on the
   * DNS hot path). force=true bypasses the TTL cache.
   */
  async refresh(force = false) {
    const now = Date.now();
    // Guard on cachedAt (not `loaded`) so a failed load throttles retries too.
    if (this.cachedAt && !force && now - this.cachedAt < CACHE_TTL_MS) return;

    if (!this.loading) {
      this.loading = (async () => {
        try {
          const raw = await this.kv.get(SETTINGS_KEY, 'text');
          if (raw) {
            let parsed = {};
            try { parsed = JSON.parse(raw); } catch { /* fall back to defaults */ }
            this.cache = { ...DEFAULT_SETTINGS, ...parsed };
          } else {
            // Read succeeded and the key is absent -> genuinely fresh install.
            this.cache = { ...DEFAULT_SETTINGS };
          }
          this.loaded = true;
        } catch {
          // Read FAILED -> keep whatever we already have; only fall back to
          // defaults on a cold start. Otherwise a transient error would
          // silently reset a user's toggles (e.g. turn idnBlock off).
          if (!this.loaded) this.cache = { ...DEFAULT_SETTINGS };
        } finally {
          this.cachedAt = Date.now();
          this.loading = null;
        }
      })();
    }
    await this.loading;
  }

  /** Zero-IO sync read (call refresh() first). */
  get() {
    return this.cache;
  }

  /** Persist a partial update; applies immediately in this isolate. */
  /** @param {Partial<FilterSettings>} patch */
  async update(patch) {
    const next = { ...this.get(), ...patch };
    await this.kv.put(SETTINGS_KEY, JSON.stringify(next));
    this.cache = next;
    this.cachedAt = Date.now();
    this.loaded = true;
  }
}
