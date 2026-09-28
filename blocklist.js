
const BLOCKLIST_URL =
  'https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/pro-plus/domains';

/**
 * Ultra-fast blocklist with subdomain matching.
 *
 * Design:
 *  - Store every domain (and only the domain, stripped of leading wildcards) in a Set.
 *  - To test "a.b.example.com": walk up the labels:
 *       a.b.example.com -> b.example.com -> example.com -> com
 *    If any of them is in the Set, it's blocked.
 *  - This gives O(labels) lookups (typically 2-4) with zero regex or trie allocation.
 */
export class Blocklist {
  constructor() {
    /** @type {Set<string>} */
    this.domains = new Set();
    this.loadedAt = 0;
    this.size = 0;
  }

  /**
   * Parse a plaintext blocklist (one domain per line).
   * Supports comments (#...), Hosts-file style, and leading wildcards `*.`.
   */
  load(text) {
    const set = new Set();
    const lines = text.split('\n');

    for (let i = 0; i < lines.length; i++) {
      let line = lines[i].trim();
      if (!line || line[0] === '#') continue;

      // Hosts-file format: "0.0.0.0 example.com" or "127.0.0.1 example.com"
      // Split on whitespace and take the last field if the first looks like an IP.
      const sp = line.indexOf(' ');
      if (sp !== -1) {
        const first = line.slice(0, sp);
        if (first === '0.0.0.0' || first === '127.0.0.1' || first === '::1') {
          line = line.slice(sp + 1).trim();
          const sp2 = line.indexOf(' ');
          if (sp2 !== -1) line = line.slice(0, sp2);
        } else {
          // Otherwise treat as single token
          line = line.slice(0, sp);
        }
      }

      // Strip leading wildcards
      if (line.startsWith('*.')) line = line.slice(2);
      else if (line.startsWith('.')) line = line.slice(1);

      // Lowercase-normalize + strip trailing dot
      if (line.endsWith('.')) line = line.slice(0, -1);

      // Remove any inline comment
      const hash = line.indexOf('#');
      if (hash !== -1) line = line.slice(0, hash).trim();
      if (!line) continue;

      const lower = line.toLowerCase();
      if (lower.length > 253) continue;

      set.add(lower);
    }

    this.domains = set;
    this.size = set.size;
    this.loadedAt = Date.now();
  }

  /**
   * Fast subdomain-aware lookup.
   * Returns true if `domain` or any of its parent domains are blocked.
   * @param {string} domain
   */
  isBlocked(domain) {
    const set = this.domains;
    let d = domain;

    // Strip trailing dot
    if (d.charCodeAt(d.length - 1) === 46 /* . */) d = d.slice(0, -1);

    // Walk up parent labels.
    // First check full domain, then strip leftmost label, repeat.
    for (;;) {
      if (set.has(d)) return true;
      const dot = d.indexOf('.');
      if (dot === -1) return false;
      // Stop early if what remains has no further dot (TLD-only check rarely matters)
      d = d.slice(dot + 1);
      // Avoid walking into bare TLDs like "com"
      const nextDot = d.indexOf('.');
      if (nextDot === -1) {
        // Still check the last label ("example.com" case when input was "a.example.com")
        return set.has(d);
      }
    }
  }
}

/**
 * Fetch and load the blocklist. Refresh periodically.
 * @param {Blocklist} blocklist
 * @param {number} refreshMs
 */
export async function refreshBlocklist(blocklist, refreshMs = 6 * 60 * 60 * 1000) {
  const load = async () => {
    try {
      const res = await fetch(BLOCKLIST_URL, {
        headers: { 'User-Agent': 'dns-filter/1.0' },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      blocklist.load(text);
      console.log(
        `[blocklist] loaded ${blocklist.size} domains at ${new Date(
          blocklist.loadedAt
        ).toISOString()}`
      );
    } catch (err) {
      console.error('[blocklist] refresh failed:', err.message);
    }
  };

  await load();
  setInterval(load, refreshMs).unref?.();
}
