export const BLOCKLIST_URL =
  'https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/pro-plus/domains';

export class Blocklist {
  constructor() {
    this.domains = new Set();
    this.loadedAt = 0;
    this.size = 0;
  }

  load(text) {
    const set = new Set();
    const lines = text.split('\n');

    for (let i = 0; i < lines.length; i++) {
      let line = lines[i].trim();
      if (!line || line[0] === '#') continue;

      const sp = line.indexOf(' ');
      if (sp !== -1) {
        const first = line.slice(0, sp);
        if (first === '0.0.0.0' || first === '127.0.0.1' || first === '::1') {
          line = line.slice(sp + 1).trim();
          const sp2 = line.indexOf(' ');
          if (sp2 !== -1) line = line.slice(0, sp2);
        } else {
          line = line.slice(0, sp);
        }
      }

      if (line.startsWith('*.')) line = line.slice(2);
      else if (line.startsWith('.')) line = line.slice(1);

      if (line.endsWith('.')) line = line.slice(0, -1);

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

  isBlocked(domain) {
    const set = this.domains;
    let d = domain;

    if (d.charCodeAt(d.length - 1) === 46) d = d.slice(0, -1);

    for (;;) {
      if (set.has(d)) return true;
      const dot = d.indexOf('.');
      if (dot === -1) return false;
      d = d.slice(dot + 1);
      if (d.indexOf('.') === -1) return set.has(d);
    }
  }
}
