export const SETTINGS_KEY = 'settings:main';
export const CACHE_TTL_MS = 30_000;

export const DEFAULT_SETTINGS = Object.freeze({
  rebindProtection: true, // block private/internal IPs in answers + internal hostnames
  idnBlock: false,        // block all punycode / non-ASCII labels (homograph defense)
});

export class SettingsStore {
  constructor(kv) {
    this.kv = kv;
    this.cache = { ...DEFAULT_SETTINGS };
    this.loaded = false;
    this.cachedAt = 0;
    this.loading = null;
  }

  /**
   * Ensure settings are loaded. Cheap no-op while cached (no I/O on the
   * DNS hot path). force=true bypasses the TTL cache.
   */
  async refresh(force = false) {
    const now = Date.now();
    if (this.loaded && !force && now - this.cachedAt < CACHE_TTL_MS) return;

    if (!this.loading) {
      this.loading = (async () => {
        try {
          const raw = await this.kv.get(SETTINGS_KEY, 'text');
          if (raw) {
            let parsed = {};
            try { parsed = JSON.parse(raw); } catch {}
            this.cache = { ...DEFAULT_SETTINGS, ...parsed };
          } else {
            this.cache = { ...DEFAULT_SETTINGS };
          }
        } catch {
          this.cache = { ...DEFAULT_SETTINGS }; // never fail closed
        } finally {
          this.loaded = true;
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
  async update(patch) {
    const next = { ...this.get(), ...patch };
    await this.kv.put(SETTINGS_KEY, JSON.stringify(next));
    this.cache = next;
    this.cachedAt = Date.now();
    this.loaded = true;
  }
}
