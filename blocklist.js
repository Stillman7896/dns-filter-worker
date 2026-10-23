// blocklist.js — Workers + Node compatible remote blocklist matcher
//
// Input is any of the common blocklist formats — plain domains, AdBlock
// (`||example.com^`), hosts-file rows, wildcards — normalized to a domain set
// (see parseBlocklist()). Several documents can be subscribed at once: each
// URL is parsed on its own and the union answers the queries, so one list can
// be replaced or dropped without re-parsing the others.
//
// The subscription list lives in KV settings (`blocklistUrls`); until the user
// saves one, the single URL comes from `env.BLOCKLIST_URL` (wrangler.toml
// [vars]). Strings are shared between the per-source sets and the merged set,
// so a union costs one extra hash table, never a second copy of the data.
//
// The URL is a *default*; the worker overrides it at runtime from settings.
import { isHttpsUrl } from './upstream.js';

export const DEFAULT_BLOCKLIST_URL =
  'https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/pro-plus/domains';

/** Hard cap on subscriptions: each one costs a fetch and a memory-resident set. */
export const MAX_BLOCKLIST_URLS = 10;

/**
 * Above this many entries in memory the Cloudflare Workers free plan can run
 * the isolate out of its 128 MB memory and the deployment starts dying with
 * OOM / "script exceeded memory limit" — the dashboard warns at this line.
 */
export const BLOCKLIST_ENTRY_LIMIT = 1_000_000;

/**
 * Validate a subscription list: https URLs only, trimmed, de-duplicated, capped
 * at MAX_BLOCKLIST_URLS. Unusable entries are dropped rather than rejected, so
 * one bad stored row can never take every other list down.
 * @param {unknown} value
 * @returns {string[]}
 */
export function normalizeBlocklistUrls(value) {
  if (!Array.isArray(value)) return [];
  /** @type {string[]} */ const out = [];
  for (const raw of value) {
    if (typeof raw !== 'string') continue;
    const url = raw.trim();
    if (!isHttpsUrl(url) || out.includes(url)) continue;
    out.push(url);
    if (out.length >= MAX_BLOCKLIST_URLS) break;
  }
  return out;
}

/**
 * The subscriptions in force: the stored list once the user has saved one,
 * otherwise the deployment default as its single entry. An empty stored list
 * is a deliberate "no remote lists" choice, not a fallback trigger.
 * @param {Pick<FilterSettings, 'blocklistUrls'>} settings
 * @param {Env} env
 * @returns {string[]}
 */
export function effectiveBlocklistUrls(settings, env) {
  if (Array.isArray(settings.blocklistUrls)) return normalizeBlocklistUrls(settings.blocklistUrls);
  const fromVar = typeof env.BLOCKLIST_URL === 'string' ? env.BLOCKLIST_URL.trim() : '';
  return fromVar ? [fromVar] : [DEFAULT_BLOCKLIST_URL];
}

/**
 * Parse one blocklist document into a blocking set plus its `@@` exceptions.
 * Accepted syntax:
 *
 *   plain domain      example.com
 *   adblock           ||example.com^   (options after $ are stripped)
 *   adblock wildcard  ||*.example.com^
 *   hosts row         0.0.0.0 example.com (also 127.0.0.1 / ::1; multiple
 *                      domains may follow the IP)
 *   exception         @@example.com or @@||example.com^ — an allow entry that
 *                      cancels a blocklist hit (blocklist scope only; custom
 *                      rules and the other filters still apply)
 *
 * Comments (`#`, `!`, `[Adblock ...]`) are skipped.
 * @param {string} text
 * @returns {{domains: Set<string>, exceptions: Set<string>}}
 */
export function parseBlocklist(text) {
  const set = new Set();
  const exceptions = new Set();
  const lines = text.split('\n');

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trim();
    if (!line || line[0] === '#' || line[0] === '!' || line[0] === '[') continue;
    let isException = false;
    if (line.startsWith('@@')) {
      // Same grammar as blocking rows, minus the `@@`: both the plain and
      // the `||domain^` dialects then parse through the normal branches.
      isException = true;
      line = line.slice(2).trim();
      if (!line || line[0] === '#') continue;
    }

    let domains;
    if (line[0] === '|') {
      // adblock ||domain^ or |domain^ — options after `$` cut first, then
      // everything from the `^` separator (covers `domain^$opt` and `domain^/path`)
      if (line[1] === '|') line = line.slice(2);
      else line = line.slice(1);
      const opt = line.indexOf('$');
      if (opt !== -1) line = line.slice(0, opt);
      const caret = line.indexOf('^');
      if (caret !== -1) line = line.slice(0, caret);
      domains = [line];
    } else {
      // hosts row: IP followed by one or more domains
      const sp = line.search(/[\s\t]/);
      if (sp !== -1) {
        const head = line.slice(0, sp).trim();
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(head) || head === '::1') {
          domains = line.slice(sp + 1).split(/\s+/);
        } else {
          continue; // trailing commentary / malformed row
        }
      } else {
        // plaintext or adblock `domain^` — a domain never contains `^`
        const caret = line.indexOf('^');
        if (caret !== -1) line = line.slice(0, caret);
        domains = [line];
      }
    }

    for (let d of domains) {
      if (d.startsWith('*.')) d = d.slice(2);
      else if (d.startsWith('.')) d = d.slice(1);
      if (d.endsWith('.')) d = d.slice(0, -1);
      if (!d) continue;

      d = d.toLowerCase();
      // plaintext format: anything with whitespace or over 253 chars is a
      // malformed line (hosts-file rows, trailing commentary), never a domain
      if (d.length > 253 || d.indexOf(' ') !== -1 || d.indexOf('\t') !== -1) continue;

      (isException ? exceptions : set).add(d);
    }
  }

  return { domains: set, exceptions };
}

/**
 * One parsed subscription document. `error` is the reason the last refresh
 * failed; `loadedAt` is 0 while the document has never been parsed, so a
 * failed source can be told apart from a fresh one.
 * @typedef {{domains: Set<string>, exceptions: Set<string>, loadedAt: number, error: string|null}} BlocklistSource
 */

export class Blocklist {
  constructor() {
    /** @type {Set<string>} merged union of every source (answers the queries) */
    this.domains = new Set();
    /** @type {Set<string>} merged `@@` exception entries */
    this.exceptions = new Set();
    this.loadedAt = 0;
    this.size = 0;
    this.exceptionSize = 0;
    /** @type {Map<string, BlocklistSource>} '' = anonymous single-document load */
    this.sources = new Map();
  }

  /**
   * Replace every source with ONE anonymous document. Back-compatible with the
   * single-list behaviour (tests, one-off parsing); the dashboard never calls
   * this — it goes through putSource() per subscription URL.
   * @param {string} text
   */
  load(text) {
    this.sources.clear();
    this.putSource('', text);
  }

  /**
   * Make the source set exactly `urls`: dropped URLs free their entries, new
   * ones wait for their first fetch. Sources whose URL stays keep their data.
   * @param {string[]} urls
   */
  setSources(urls) {
    let changed = false;
    for (const url of [...this.sources.keys()]) {
      if (url !== '' && !urls.includes(url)) {
        this.sources.delete(url);
        changed = true;
      }
    }
    for (const url of urls) {
      if (!this.sources.has(url)) {
        this.sources.set(url, { domains: new Set(), exceptions: new Set(), loadedAt: 0, error: null });
        changed = true;
      }
    }
    if (changed) this.rebuild();
  }

  /**
   * Parse `text` as the document behind `url` and merge it into the union.
   * @param {string} url
   * @param {string} text
   */
  putSource(url, text) {
    const parsed = parseBlocklist(text);
    this.sources.set(url, { domains: parsed.domains, exceptions: parsed.exceptions, loadedAt: Date.now(), error: null });
    this.rebuild();
  }

  /**
   * A 304 answered for this URL: the document we already hold is current, so
   * only its freshness marker moves. A source that was never parsed ignores it.
   * @param {string} url
   */
  touchSource(url) {
    const s = this.sources.get(url);
    if (s && s.loadedAt) {
      s.loadedAt = Date.now();
      s.error = null;
    }
  }

  /**
   * Note why the last refresh of `url` failed. The previous document stays in
   * use (stale-if-error), so filtering never stops because GitHub blinked.
   * @param {string} url
   * @param {string} message
   */
  sourceError(url, message) {
    const s = this.sources.get(url);
    if (s) s.error = message;
  }

  /** @param {string} url @returns {boolean} true once the URL has been parsed */
  sourceLoaded(url) {
    const s = this.sources.get(url);
    return Boolean(s && s.loadedAt);
  }

  /** @param {string} url @param {number} maxAge @returns {boolean} */
  sourceFresh(url, maxAge) {
    const s = this.sources.get(url);
    return Boolean(s && s.loadedAt && Date.now() - s.loadedAt < maxAge);
  }

  /** Recompute the merged sets from the sources (shared string references). */
  rebuild() {
    const domains = new Set();
    const exceptions = new Set();
    let loadedAt = 0;
    for (const s of this.sources.values()) {
      for (const d of s.domains) domains.add(d);
      for (const e of s.exceptions) exceptions.add(e);
      if (s.loadedAt > loadedAt) loadedAt = s.loadedAt;
    }
    this.domains = domains;
    this.exceptions = exceptions;
    this.size = domains.size;
    this.exceptionSize = exceptions.size;
    this.loadedAt = loadedAt;
  }

  /**
   * Per-subscription numbers for the dashboard, sorted for a stable render.
   * The anonymous single-document load (`''`) is not a subscription and stays
   * out of the list.
   * @returns {Array<{url: string, entries: number, exceptions: number, loadedAt: number, error: string|null}>}
   */
  listSources() {
    const out = [];
    for (const [url, s] of this.sources) {
      if (!url) continue;
      out.push({ url, entries: s.domains.size, exceptions: s.exceptions.size, loadedAt: s.loadedAt, error: s.error });
    }
    out.sort((a, b) => a.url.localeCompare(b.url));
    return out;
  }

  /**
   * Returns the exact entry matching `domain` (walking up parent labels), or
   * null. Shared by the block set and the exception set.
   * @param {Set<string>} set
   * @param {string} domain
   * @returns {string|null}
   */
  walk(set, domain) {
    let d = domain;
    if (d.charCodeAt(d.length - 1) === 46) d = d.slice(0, -1);

    for (;;) {
      if (set.has(d)) return d;
      const dot = d.indexOf('.');
      if (dot === -1) return null;
      d = d.slice(dot + 1);
      if (d.indexOf('.') === -1) return set.has(d) ? d : null;
    }
  }

  /**
   * Returns the exact blocklist entry that matches `domain` (walking up
   * parent labels), or null if not blocked.
   * @param {string} domain
   * @returns {string|null}
   */
  match(domain) {
    return this.walk(this.domains, domain);
  }

  /**
   * Returns the `@@` exception entry that matches `domain`, or null.
   * @param {string} domain
   * @returns {string|null}
   */
  exception(domain) {
    return this.exceptions.size ? this.walk(this.exceptions, domain) : null;
  }

  /** @param {string} domain @returns {boolean} */
  isBlocked(domain) {
    if (this.exception(domain)) return false;
    return this.match(domain) !== null;
  }

  /**
   * Every `@@` exception entry, as allow-rule rows for the rules view.
   * @returns {Array<{domain: string, kind: 'allow', src: 'blocklist'}>}
   */
  exceptionRules() {
    /** @type {Array<{domain: string, kind: 'allow', src: 'blocklist'}>} */ const out = [];
    for (const domain of this.exceptions) out.push({ domain, kind: 'allow', src: 'blocklist' });
    out.sort((a, b) => a.domain.localeCompare(b.domain));
    return out;
  }
}
