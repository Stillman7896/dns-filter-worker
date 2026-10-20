// idn.js — Internationalized domain names: Unicode <-> punycode (A-labels).
//
// DNS itself only ever carries ASCII labels, so anything a human types has to
// be converted before it can be matched against blocklists, rules or the wire.
// Both directions live here because they are easy to get wrong and cheap to
// share: rules.js normalizes with toAscii(), the dashboard renders with
// toUnicode().
//
// toAscii() leans on the WHATWG URL parser, which implements the full UTS-46
// mapping table (ß, case folding, fullwidth forms, ideographic dots) instead
// of the bare RFC 3492 algorithm — the same thing the browser address bar does.
// toUnicode() only needs the decode half, so it is written out below.

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const MAX_LABEL = 63; // an A-label cannot be longer than this on the wire

/** Map one ASCII digit of a punycode payload to its RFC 3492 value.
 * @param {number} c @returns {number} */
function decodeDigit(c) {
  if (c >= 48 && c <= 57) return c - 22;     // 0-9 -> 26..35
  if (c >= 97 && c <= 122) return c - 97;     // a-z
  if (c >= 65 && c <= 90) return c - 65;      // A-Z
  return BASE;
}

/** @param {number} delta @param {number} points @param {boolean} first @returns {number} */
function adapt(delta, points, first) {
  let d = first ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / points);
  let k = 0;
  while (d > ((BASE - TMIN) * TMAX) >> 1) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return Math.floor(k + ((BASE - TMIN + 1) * d) / (d + SKEW));
}

/** Decode the payload of one label (the "xn--" prefix already removed).
 * Throws on malformed input — callers decide whether that is fatal.
 * @param {string} payload @returns {string} */
export function punycodeDecode(payload) {
  if (typeof payload !== 'string') throw new Error('not a string');
  // payload is an A-label minus its "xn--" prefix, so the wire label is four
  // bytes longer; anything past MAX_LABEL could never resolve anyway.
  if (payload.length + 4 > MAX_LABEL) throw new Error('label too long');
  const output = [];
  const split = payload.lastIndexOf('-');
  const basic = split < 0 ? 0 : split;
  for (let i = 0; i < basic; i++) {
    const c = payload.charCodeAt(i);
    if (c >= 0x80) throw new Error('non-ascii literal half');
    output.push(c);
  }

  let index = basic > 0 ? basic + 1 : 0;
  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;

  while (index < payload.length) {
    const old = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (index >= payload.length) throw new Error('truncated payload');
      const digit = decodeDigit(payload.charCodeAt(index++));
      if (digit >= BASE) throw new Error('bad digit');
      if (i > 0x10ffff - digit * w) throw new Error('overflow'); // refuse wrap-around
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      if (w > 0x10ffff / (BASE - t)) throw new Error('overflow');
      w *= BASE - t;
    }
    bias = adapt(i - old, output.length + 1, old === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    output.splice(i, 0, n);
    i += 1;
  }
  return String.fromCodePoint(...output);
}

/** Punycode (ASCII) form of a name the user may have typed in their own script.
 * Anything already ASCII, or any label that fails to decode, passes through
 * untouched — this is a translation, not a validator.
 * @param {string} name @returns {string} */
export function toUnicode(name) {
  if (typeof name !== 'string' || !name.toLowerCase().includes('xn--')) return typeof name === 'string' ? name : '';
  return name
    .split('.')
    .map((label) => {
      if (!/^xn--/i.test(label)) return label;
      try {
        return punycodeDecode(label.slice(4)) || label; // empty payload keeps the label
      } catch {
        return label; // not really an A-label; leave it be
      }
    })
    .join('.');
}

/** Wire form of a name typed with foreign characters (IDN -> punycode), or ''
 * when the parser refuses it. Empty input stays empty instead of becoming ''.
 * @param {string} name @returns {string} */
export function toAscii(name) {
  if (typeof name !== 'string' || !name) return '';
  try {
    const host = new URL(`http://${name}`).hostname;
    // Trailing-dot hosts are legal input ("example.com.") but never useful
    // output — IDNA maps U+3002 and friends to "." too.
    return host.endsWith('.') ? host.slice(0, -1) : host;
  } catch {
    return '';
  }
}
