// blocklist.js — Workers + Node compatible remote blocklist matcher
//
// Input is any of the common blocklist formats — plain domains, AdBlock
// (`||example.com^`), hosts-file rows, wildcards — normalized to a domain set
// (see load()). The URL is a *default*; the worker overrides it at runtime
// from `env.BLOCKLIST_URL` (wrangler.toml [vars]).
export const DEFAULT_BLOCKLIST_URL =
  'https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/pro-plus/domains';

export class Blocklist {
  constructor() {
    this.domains = new Set();
    /** @type {Set<string>} `@@` exception entries from the same file. */
    this.exceptions = new Set();
    this.loadedAt = 0;
    this.size = 0;
    this.exceptionSize = 0;
  }

  /**
   * Parse one blocklist format into a plain domain set. Accepted syntax:
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
   */
  load(text) {
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

    this.domains = set;
    this.size = set.size;
    this.exceptions = exceptions;
    this.exceptionSize = exceptions.size;
    this.loadedAt = Date.now();
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
    /** @type {Array<{domain: string, kind: 'allow', src: 'blocklist'}>} */
    const out = [];
    for (const domain of this.exceptions) out.push({ domain, kind: 'allow', src: 'blocklist' });
    out.sort((a, b) => a.domain.localeCompare(b.domain));
    return out;
  }
}
