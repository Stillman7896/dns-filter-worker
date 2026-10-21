// filters.js — Pure DNS filtering logic shared by worker.js and the test suite.
//
// No I/O here: every store is injected, so tests pass in-memory instances
// and worker.js passes the KV-backed singletons. Layer order:
//   route > denylist > allowlist > blocklist > tld > keyword > rebinding > idn > none

/** RFC 6761/6762 special-use TLDs (single label) that must never reach upstream. */
export const INTERNAL_TLDS = new Set([
  'local', 'localdomain', 'lan', 'home', 'internal', 'intranet', 'corp',
  'private', 'home.arpa', 'test', 'invalid', 'example', 'localhost',
]);

/** Statuses answered with NXDOMAIN instead of forwarded. */
export const BLOCKED_QUERY_STATUSES = new Set([
  'deny', 'blocklist', 'tld', 'keyword', 'regex', 'rebind', 'idn',
]);

/** Last label of a lowercased FQDN, or ''.
 * @param {string} name
 * @returns {string}
 */
export function tldOf(name) {
  const dot = name.lastIndexOf('.');
  return dot === -1 ? '' : name.slice(dot + 1);
}

/** Multi-label internal suffixes (matched as name or parent suffix). */
export const INTERNAL_SUFFIXES = [
  'home.arpa',
  'localhost',
  'localhost.localdomain',
];

/** Returns the special-use name / TLD that matched, or null.
 * @param {string} name
 * @returns {string|null}
 */
export function rebindNameHit(name) {
  for (const s of INTERNAL_SUFFIXES) {
    if (name === s || name.endsWith('.' + s)) return s;
  }
  const tld = tldOf(name);
  return INTERNAL_TLDS.has(tld) ? tld : null;
}

/**
 * IDN homograph detection — block-all/off strategy: any punycode (xn--)
 * label, or non-ASCII bytes from non-compliant clients.
 * @returns {string|null} offending label or null
 * @param {string} name
 */
export function idnHit(name) {
  let start = 0;
  for (;;) {
    const dot = name.indexOf('.', start);
    const label = dot === -1 ? name.slice(start) : name.slice(start, dot);
    if (label.startsWith('xn--')) return label;
    if (dot === -1) break;
    start = dot + 1;
  }
  if (/[\x80-\uffff]/.test(name)) return '<non-ascii>';
  return null;
}

/**
 * Ordered query-side decision chain (synchronous — stores must already be
 * refreshed by the caller).
 *
 * A response route comes first: it is a direct answer for the name, so it
 * outranks even an explicit deny rule. The caller turns `verdict.route` into
 * answer records with routeRecords().
 * @param {{ruleStore: {match(name: string): {kind:'allow'|'deny', at:string}|null}, blocklist: {match(name: string): string|null, exception?: (name: string) => string|null}, keywordStore: {get(): Set<string>}, regex: {test(name: string): string|null}, tldStore: {get(): Set<string>}, routeStore?: {match(name: string): ({type:'a'|'aaaa'|'cname', value:string, ttl:number}&{at:string})|null}}} stores
 * @param {Pick<FilterSettings, 'rebindProtection'|'idnBlock'|'tldBlock'|'keywordBlock'|'regexBlock'>} settings
 * @param {string} name lowercase QNAME
 * @returns {{status:string, filter:string, matched:string|null, route?:{type:'a'|'aaaa'|'cname', value:string, ttl:number, at:string}}}
 */
export function runQueryFilters(stores, settings, name) {
  const { ruleStore, blocklist, keywordStore, regex, tldStore, routeStore } = stores;

  // 0. response route — a fixed answer for this name and its subdomains
  const route = routeStore && routeStore.match(name);
  if (route) {
    return {
      status: 'route',
      filter: 'route',
      matched: route.at,
      route: { type: route.type, value: route.value, ttl: route.ttl, at: route.at },
    };
  }

  // 1-2. custom allow / deny — allow wins across every parent level
  const custom = ruleStore.match(name);
  if (custom) {
    return custom.kind === 'allow'
      ? { status: 'allow', filter: 'allowlist', matched: custom.at }
      : { status: 'deny', filter: 'denylist', matched: custom.at };
  }

  // 3. remote blocklist (Hagezi pro-plus); a `@@` exception in the same file
  // cancels this verdict only — deny rules, TLD/keyword/regex still apply.
  const blockHit = blocklist.match(name);
  const blockExcept = blocklist.exception ? blocklist.exception(name) : null;
  if (blockHit && !blockExcept) return { status: 'blocklist', filter: 'blocklist', matched: blockHit };

  // 4. TLD policy — one Set lookup on the last label
  if (settings.tldBlock) {
    const tlds = tldStore.get();
    if (tlds.size) {
      const tld = tldOf(name);
      if (tld && tlds.has(tld)) return { status: 'tld', filter: 'tld', matched: tld };
    }
  }

  // 5. keyword substring match — K passes over an ~L-char string
  if (settings.keywordBlock) {
    const kws = keywordStore.get();
    if (kws.size) {
      for (const kw of kws) {
        if (name.includes(kw)) return { status: 'keyword', filter: 'keyword', matched: kw };
      }
    }
  }

  // 5b. regex match — one test per compiled pattern; a set identity change
  //     re-compiles, so a KV refresh is picked up on the next query.
  if (settings.regexBlock) {
    const hit = regex.test(name);
    if (hit) return { status: 'regex', filter: 'regex', matched: hit };
  }

  // 6. DNS rebinding — internal / special-use names
  if (settings.rebindProtection) {
    const hit = rebindNameHit(name);
    if (hit) return { status: 'rebind', filter: 'rebind', matched: hit };
  }

  // 7. IDN homograph
  if (settings.idnBlock) {
    const hit = idnHit(name);
    if (hit) return { status: 'idn', filter: 'idn', matched: hit };
  }

  return { status: 'none', filter: 'upstream', matched: null };
}

// ---- Answer-level rebinding: private IP inspection (works on Buf or Uint8Array) ----

/** @param {Uint8Array} b @param {number} o @returns {number} */
function rd16(b, o) { return ((b[o] & 0xff) << 8) | (b[o + 1] & 0xff); }

/** @param {Uint8Array} b @param {number} o @returns {boolean} */
export function isPrivateV4(b, o) {
  const ip = ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  if ((ip >>> 24) === 10) return true;                              // 10/8
  if ((ip >>> 20) === (0xac100000 >>> 20)) return true;             // 172.16/12
  if ((ip >>> 16) === 0xc0a8) return true;                          // 192.168/16
  if ((ip >>> 24) === 127) return true;                             // 127/8
  if ((ip >>> 16) === 0xa9fe) return true;                          // 169.254/16 (metadata)
  if ((ip >>> 22) === (0x64400000 >>> 22)) return true;             // 100.64/10 (CGNAT)
  return ip === 0;
}

/** @param {Uint8Array} b @param {number} o @returns {boolean} */
export function isPrivateV6(b, o) {
  let allZero = true;
  for (let i = o; i < o + 16; i++) if (b[i]) { allZero = false; break; }
  if (allZero) return true;                                          // ::

  let z = true;
  for (let i = o; i < o + 15; i++) if (b[i]) { z = false; break; }
  if (z && b[o + 15] === 1) return true;                             // ::1

  if ((b[o] & 0xfe) === 0xfc) return true;                           // fc00::/7
  if (b[o] === 0xfe && (b[o + 1] & 0xc0) === 0x80) return true;      // fe80::/10

  let mapped = true;
  for (let i = o; i < o + 10; i++) if (b[i]) { mapped = false; break; }
  if (mapped && b[o + 10] === 0xff && b[o + 11] === 0xff) return isPrivateV4(b, o + 12);
  return false;
}

/** @param {Uint8Array} buf @param {number} off @returns {number} */
function skipNameAt(buf, off) {
  let jumps = 0;
  while (off < buf.length) {
    const len = buf[off];
    if (len === 0) return off + 1;
    if ((len & 0xc0) === 0xc0) return off + 2; // compression pointer
    off += 1 + len;
    if (++jumps > 255) return -1;
  }
  return -1;
}

/** @param {Uint8Array} b @param {number} o @returns {string} */
function fmtV4(b, o) { return `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`; }

/**
 * Walk the ANSWER section of a DNS response and return the first private /
 * link-local A or AAAA address found, or null if all answers are public.
 * @param {Uint8Array|null} buf
 * @returns {string|null}
 */
export function privateAnswerIP(buf) {
  if (!buf || buf.length < 12) return null;
  const qd = rd16(buf, 4);
  const an = rd16(buf, 6);
  let off = 12;

  for (let i = 0; i < qd; i++) {
    const r = skipNameAt(buf, off);
    if (r < 0) return null;
    off = r + 4;
    if (off > buf.length) return null;
  }

  for (let i = 0; i < an; i++) {
    const r = skipNameAt(buf, off);
    if (r < 0) return null;
    if (r + 10 > buf.length) return null;
    const type = rd16(buf, r);
    const rdlen = rd16(buf, r + 8);
    const rd = r + 10;
    if (type === 1 && rdlen === 4 && isPrivateV4(buf, rd)) return fmtV4(buf, rd);
    if (type === 28 && rdlen === 16 && isPrivateV6(buf, rd)) return '<private-v6>';
    off = rd + rdlen;
    if (off > buf.length) return null;
  }
  return null;
}
/**
 * Lazy regex matcher over a set of patterns. Compiles on first use and only
 * re-compiles when the backing Set is replaced (a KV refresh), so the hot
 * path is one `RegExp.test` per pattern — no allocation per query.
 * Entries are [pattern, RegExp] pairs so a failed compile can never shift
 * the pattern reported back.
 */
export class RegexEngine {
  /** @param {{get(): Set<string>}} store */
  constructor(store) {
    this.store = store;
    /** @type {Set<string>|null} */ this.compiledSet = null;
    /** @type {Array<[string, RegExp]>} */ this.regexes = [];
  }

  /** @param {string} name @returns {string|null} the pattern that matched, or null */
  test(name) {
    const set = this.store.get();
    if (set !== this.compiledSet) {
      /** @type {Array<[string, RegExp]>} */
      const compiled = [];
      for (const p of set) {
        try { compiled.push([p, new RegExp(p, 'i')]); } catch { /* validated at store; skip anyway */ }
      }
      this.regexes = compiled;
      this.compiledSet = set;
    }
    const re = this.regexes;
    for (let i = 0; i < re.length; i++) {
      if (re[i][1].test(name)) return re[i][0];
    }
    return null;
  }
}
