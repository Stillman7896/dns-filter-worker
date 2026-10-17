// blocklist.js — Workers + Node compatible remote blocklist matcher
//
// Expected input is a PLAINTEXT domain list, one domain per line:
//
//   example.com
//   sub.domain.com
//
// Blank lines and `#` comments are skipped; so is any line that is not a
// single domain (whitespace, over-length). The URL is a *default*; the worker
// overrides it at runtime from `env.BLOCKLIST_URL` (wrangler.toml [vars]).
export const DEFAULT_BLOCKLIST_URL =
  'https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/pro-plus/domains';

export class Blocklist {
  constructor() {
    this.domains = new Set();
    this.loadedAt = 0;
    this.size = 0;
  }

  /** @param {string} text */
  load(text) {
    const set = new Set();
    const lines = text.split('\n');

    for (let i = 0; i < lines.length; i++) {
      let line = lines[i].trim();
      if (!line || line[0] === '#') continue;

      if (line.startsWith('*.')) line = line.slice(2);
      else if (line.startsWith('.')) line = line.slice(1);
      if (line.endsWith('.')) line = line.slice(0, -1);
      if (!line) continue;

      line = line.toLowerCase();
      // plaintext format: anything with whitespace or over 253 chars is a
      // malformed line (hosts-file rows, trailing commentary), never a domain
      if (line.length > 253 || line.indexOf(' ') !== -1 || line.indexOf('\t') !== -1) continue;

      set.add(line);
    }

    this.domains = set;
    this.size = set.size;
    this.loadedAt = Date.now();
  }

  /**
   * Returns the exact blocklist entry that matches `domain` (walking up
   * parent labels), or null if not blocked.
   * @param {string} domain
   * @returns {string|null}
   */
  match(domain) {
    const set = this.domains;
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

  /** @param {string} domain @returns {boolean} */
  isBlocked(domain) {
    return this.match(domain) !== null;
  }
}
