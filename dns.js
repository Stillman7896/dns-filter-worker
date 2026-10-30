// dns.js — Workers + Node compatible DNS message helpers (no node:buffer)

// ---------- Minimal Buffer shim (Uint8Array + BE accessors) ----------
class Buf extends Uint8Array {
  // @ts-expect-error — Buf.from deliberately accepts more inputs than Uint8Array.from
  static from(x) {
    if (x instanceof Uint8Array) {
      const b = new Buf(x.byteLength);
      b.set(x);
      return b;
    }
    if (typeof x === 'string') {
      const b = new Buf(x.length);
      for (let i = 0; i < x.length; i++) b[i] = x.charCodeAt(i) & 0xff;
      return b;
    }
    if (typeof x === 'number') return new Buf(x);
    if (x && typeof x.byteLength === 'number') {
      const b = new Buf(x.byteLength);
      b.set(new Uint8Array(x));
      return b;
    }
    throw new Error('Buf.from: unsupported input');
  }

  /** @param {unknown} x @returns {boolean} */
  static isBuffer(x) {
    return x instanceof Buf || x instanceof Uint8Array;
  }

  /**
   * @param {number} o
   * @returns {number}
   */

  /** @param {number} o @returns {number} */
  readUInt16BE(o) {
    return (this[o] << 8) | this[o + 1];
  }

  /** @param {number} o @returns {number} */
  readUInt32BE(o) {
    return (
      this[o] * 0x1000000 +
      ((this[o + 1] << 16) | (this[o + 2] << 8) | this[o + 3])
    );
  }

  /** @param {number} v @param {number} o */
  writeUInt16BE(v, o) {
    this[o] = (v >>> 8) & 0xff;
    this[o + 1] = v & 0xff;
  }

  /** @param {number} v @param {number} o */
  writeUInt32BE(v, o) {
    this[o] = (v >>> 24) & 0xff;
    this[o + 1] = (v >>> 16) & 0xff;
    this[o + 2] = (v >>> 8) & 0xff;
    this[o + 3] = v & 0xff;
  }

  /**
   * @param {string} [_enc]
   * @param {number} [s]
   * @param {number} [e]
   * @returns {string}
   */
  toString(_enc, s, e) {
    s = s ?? 0;
    e = e ?? this.length;
    let out = '';
    for (let i = s; i < e; i++) out += String.fromCharCode(this[i]);
    return out;
  }
}

export { Buf };

/**
 * Parse QNAME out of a raw DNS query (wire format).
 * @param {Buf|Uint8Array} buf
 * @returns {{ name: string, qtype: number, qclass: number } | null}
 */
/**
 * @param {Uint8Array|null} buf
 * @returns {{name:string, qtype:number, qclass:number}|null}
 */
export function parseQuestion(buf) {
  if (!buf || buf.length < 12) return null;

  const qdcount = (buf[4] << 8) | buf[5];
  if (qdcount < 1) return null;

  let off = 12;
  const labels = [];
  let jumps = 0;

  while (off < buf.length) {
    const len = buf[off];

    if (len === 0) {
      off += 1;
      break;
    }

    if ((len & 0xc0) === 0xc0) {
      if (off + 1 >= buf.length) return null;
      const ptr = ((len & 0x3f) << 8) | buf[off + 1];
      if (++jumps > 16) return null;
      off = ptr;
      continue;
    }

    if (len > 63 || off + 1 + len > buf.length) return null;
    let label = '';
    for (let i = off + 1; i < off + 1 + len; i++) {
      const c = buf[i];
      label += String.fromCharCode(c >= 65 && c <= 90 ? c + 32 : c);
    }
    labels.push(label);
    off += 1 + len;
  }

  if (buf.length < off + 4) return null;
  const qtype = (buf[off] << 8) | buf[off + 1];
  const qclass = (buf[off + 2] << 8) | buf[off + 3];
  return { name: labels.join('.'), qtype, qclass };
}

/** @param {Uint8Array} queryBuf @returns {Buf} */
export function buildNxdomainResponse(queryBuf) {
  const out = Buf.from(queryBuf);
  const flags = out.readUInt16BE(2);
  out.writeUInt16BE(0x8000 | 0x0080 | (flags & 0x0100) | 0x0003, 2);
  out.writeUInt16BE(0, 6);
  out.writeUInt16BE(0, 8);
  out.writeUInt16BE(0, 10);
  return out;
}

/** @param {Uint8Array} queryBuf @param {string} [responseType] @param {number} [qtype] @returns {Buf} */
export function buildBlockedResponse(queryBuf, responseType = 'nxdomain', qtype = RR.A) {
  if (responseType === 'refused') return buildRefusedResponse(queryBuf);
  if (responseType === 'nodata') {
    const end = questionEnd(queryBuf);
    if (end < 0) return buildRefusedResponse(queryBuf);
    const flags = (queryBuf[2] << 8) | queryBuf[3];
    const head = Buf.from(queryBuf.subarray(0, end));
    head.writeUInt16BE(0x8000 | 0x0400 | 0x0080 | (flags & 0x0100), 2);
    head.writeUInt16BE(1, 4);
    head.writeUInt16BE(0, 6);
    head.writeUInt16BE(0, 8);
    head.writeUInt16BE(0, 10);
    return head;
  }
  if (responseType === 'null_ip') {
    if (questionEnd(queryBuf) < 0) return buildRefusedResponse(queryBuf);
    const q = parseQuestion(queryBuf);
    const name = q ? q.name : 'blocked.local';
    // The query type decides the answer: an AAAA query must not be handed a
    // 4-byte A record (some clients reject the mismatch outright).
    const isAaaa = (q && q.qtype === RR.AAAA) || qtype === RR.AAAA;
    const rdata = isAaaa ? NULL_IPV6 : NULL_IPV4;
    return buildAnswerResponse(queryBuf, [{ name, type: isAaaa ? RR.AAAA : RR.A, rdata, ttl: NULL_IP_TTL }]);
  }
  return buildNxdomainResponse(queryBuf);
}

/** TTL for a synthesized null-address answer: short enough to re-check soon. */
const NULL_IP_TTL = 300;
/** Rdata for a null-address block, shared and never mutated after creation. */
const NULL_IPV4 = new Buf(4); // 0.0.0.0
const NULL_IPV6 = new Buf(16); // ::

// ---- Synthesized answers (domain response routing, upstream probe) ----

/** DNS RR type numbers this worker can synthesize. */
export const RR = Object.freeze({ A: 1, CNAME: 5, AAAA: 28 });

/** Concatenate byte arrays.
 * @param {Uint8Array[]} parts @returns {Buf}
 */
export function joinBufs(parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Buf(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Offset just past the question section (QNAME + QTYPE + QCLASS), or -1.
 * @param {Uint8Array|null} buf @returns {number}
 */
export function questionEnd(buf) {
  if (!buf || buf.length < 12) return -1;
  const qd = (buf[4] << 8) | buf[5];
  if (qd < 1) return -1;
  let off = 12;
  for (let i = 0; i < qd; i++) {
    off = skipName(buf, off);
    if (off < 0 || off + 4 > buf.length) return -1;
    off += 4;
  }
  return off;
}

/** Wire-format QNAME for a dotted name (uncompressed).
 * @param {string} name @returns {Buf}
 */
export function encodeName(name) {
  const labels = name.split('.').filter(Boolean);
  let len = 1;
  for (const l of labels) len += 1 + l.length;
  const out = new Buf(len);
  let off = 0;
  for (const l of labels) {
    out[off++] = l.length;
    for (let i = 0; i < l.length; i++) out[off++] = l.charCodeAt(i) & 0xff;
  }
  out[off] = 0; // root label
  return out;
}

/** @param {unknown} raw @returns {Buf|null} */
export function parseIpv4(raw) {
  if (typeof raw !== 'string') return null;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(raw.trim());
  if (!m) return null;
  const out = new Buf(4);
  for (let i = 0; i < 4; i++) {
    const n = Number(m[i + 1]);
    if (n > 255) return null;
    out[i] = n;
  }
  return out;
}

/** Accepts `::`, v4-mapped and trailing-IPv4 forms.
 * @param {unknown} raw @returns {Buf|null}
 */
export function parseIpv6(raw) {
  if (typeof raw !== 'string') return null;
  let s = raw.trim();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const zone = s.indexOf('%');
  if (zone !== -1) s = s.slice(0, zone);
  if (s.indexOf(':') === -1) return null;

  const lastColon = s.lastIndexOf(':');
  const v4 = parseIpv4(s.slice(lastColon + 1));
  if (v4) {
    const hi = ((v4[0] << 8) | v4[1]).toString(16);
    const lo = ((v4[2] << 8) | v4[3]).toString(16);
    s = s.slice(0, lastColon + 1) + hi + ':' + lo;
  }

  const chunks = s.split('::');
  if (chunks.length > 2) return null;
  /** @param {string} c @returns {number[]|null} */
  const words = (c) => {
    if (c === '') return [];
    const out = [];
    for (const g of c.split(':')) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = words(chunks[0]);
  const tail = chunks.length === 2 ? words(chunks[1]) : [];
  if (!head || !tail) return null;

  let groups;
  if (chunks.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null; // '::' must stand for at least one group
    groups = [...head, ...new Array(fill).fill(0), ...tail];
  } else {
    if (head.length !== 8) return null;
    groups = head;
  }

  const out = new Buf(16);
  for (let i = 0; i < 8; i++) out.writeUInt16BE(groups[i], i * 2);
  return out;
}

/**
 * Synthesize a response: the question is echoed byte for byte and `answers`
 * are appended with an explicit (uncompressed) owner name. An empty answer
 * list is NODATA (NOERROR, ANCOUNT 0) — used for overridden names that have no
 * record of the queried type.
 * @param {Uint8Array} queryBuf
 * @param {Array<{name: string, type: number, rdata: Uint8Array, ttl: number}>} answers
 * @returns {Buf}
 */
export function buildAnswerResponse(queryBuf, answers) {
  const end = questionEnd(queryBuf);
  if (end < 0) return buildRefusedResponse(queryBuf);

  const flags = (queryBuf[2] << 8) | queryBuf[3];
  // QR | AA | RA, RD copied from the query.
  const head = Buf.from(queryBuf.subarray(0, end));
  head.writeUInt16BE(0x8000 | 0x0400 | 0x0080 | (flags & 0x0100), 2);
  head.writeUInt16BE(1, 4);
  head.writeUInt16BE(answers.length, 6);
  head.writeUInt16BE(0, 8);
  head.writeUInt16BE(0, 10);

  const parts = [head];
  for (const a of answers) {
    const name = encodeName(a.name);
    const rr = new Buf(name.length + 10 + a.rdata.length);
    rr.set(name, 0);
    rr.writeUInt16BE(a.type, name.length);
    rr.writeUInt16BE(1, name.length + 2); // class IN
    rr.writeUInt32BE(Math.max(0, Math.floor(a.ttl)) >>> 0, name.length + 4);
    rr.writeUInt16BE(a.rdata.length, name.length + 8);
    rr.set(a.rdata, name.length + 10);
    parts.push(rr);
  }
  return joinBufs(parts);
}

/** Recursive query for the upstream probe (id 0: the answer's ID is unused).
 * @param {string} name @param {number} [qtype] @returns {Buf}
 */
export function buildQueryMessage(name, qtype = RR.A) {
  const qname = encodeName(name);
  const out = new Buf(12 + qname.length + 4);
  out.writeUInt16BE(0, 0);
  out.writeUInt16BE(0x0100, 2); // RD
  out.writeUInt16BE(1, 4);
  out.set(qname, 12);
  out.writeUInt16BE(qtype, 12 + qname.length);
  out.writeUInt16BE(1, 14 + qname.length);
  return out;
}

/**
 * Fold a response message into what the probe and logs need: rcode, answer
 * count, and the first A/AAAA record as text.
 * @param {Uint8Array|null} buf
 * @returns {{rcode: number, count: number, sample: string|null}|null}
 */
export function summariseAnswers(buf) {
  if (!buf || buf.length < 12) return null;
  const rcode = buf[3] & 0x0f;
  const qd = (buf[4] << 8) | buf[5];
  const an = (buf[6] << 8) | buf[7];

  let off = 12;
  for (let i = 0; i < qd; i++) {
    off = skipName(buf, off);
    if (off < 0) return { rcode, count: 0, sample: null };
    off += 4;
    if (off > buf.length) return { rcode, count: 0, sample: null };
  }

  let sample = null;
  for (let i = 0; i < an; i++) {
    off = skipName(buf, off);
    if (off < 0 || off + 10 > buf.length) break;
    const type = (buf[off] << 8) | buf[off + 1];
    const rdlen = (buf[off + 8] << 8) | buf[off + 9];
    const rd = off + 10;
    if (rd + rdlen > buf.length) break;
    if (sample === null && type === RR.A && rdlen === 4) {
      sample = `${buf[rd]}.${buf[rd + 1]}.${buf[rd + 2]}.${buf[rd + 3]}`;
    } else if (sample === null && type === RR.AAAA && rdlen === 16) {
      const groups = [];
      for (let g = 0; g < 8; g++) groups.push(((buf[rd + g * 2] << 8) | buf[rd + g * 2 + 1]).toString(16));
      sample = groups.join(':');
    }
    off = rd + rdlen;
  }
  return { rcode, count: an, sample };
}

/** @param {Uint8Array} queryBuf @returns {Buf} */
export function buildRefusedResponse(queryBuf) {
  const out = Buf.from(queryBuf);
  const flags = out.readUInt16BE(2);
  out.writeUInt16BE(0x8000 | 0x0080 | (flags & 0x0100) | 0x0005, 2);
  out.writeUInt16BE(0, 6);
  out.writeUInt16BE(0, 8);
  out.writeUInt16BE(0, 10);
  return out;
}

/** Degenerate/null buffers fall back to the default TTL (60s).
 * @param {Uint8Array|null} respBuf
 * @returns {number}
 */
export function minTtl(respBuf) {
  if (!respBuf || respBuf.length < 12) return 60;

  const qd = (respBuf[4] << 8) | respBuf[5];
  const an = (respBuf[6] << 8) | respBuf[7];
  const ns = (respBuf[8] << 8) | respBuf[9];
  const ar = (respBuf[10] << 8) | respBuf[11];
  const totalRR = an + ns + ar;
  if (totalRR === 0) return 60;

  let off = 12;
  for (let i = 0; i < qd; i++) {
    off = skipName(respBuf, off);
    if (off < 0) return 60;
    off += 4;
    if (off > respBuf.length) return 60;
  }

  let min = Infinity;
  for (let i = 0; i < totalRR; i++) {
    off = skipName(respBuf, off);
    if (off < 0) return 60;
    if (off + 10 > respBuf.length) return 60;
    // Open-coded u32 read: works on Buf and plain Uint8Array alike.
    const ttl =
      respBuf[off + 4] * 0x1000000 +
      ((respBuf[off + 5] << 16) | (respBuf[off + 6] << 8) | respBuf[off + 7]);
    if (ttl < min) min = ttl;
    const rdlen = (respBuf[off + 8] << 8) | respBuf[off + 9];
    off += 10 + rdlen;
    if (off > respBuf.length) return 60;
  }

  if (!Number.isFinite(min) || min <= 0) return 60;
  // Cap: bounds how long both the client and the edge cache may reuse the
  // answer (an hour matches ordinary resolver behaviour for long-TTL records).
  return Math.min(min, 3600);
}

/**
 * True when the query carries an EDNS OPT record with the DO (DNSSEC OK) bit.
 * Used to split the answer cache: a validating client must not be served a
 * stripped (non-DNSSEC) answer cached for a plain query, and vice versa.
 * @param {Uint8Array} buf
 * @returns {boolean}
 */
export function ednsDo(buf) {
  if (!buf || buf.length < 12) return false;
  const qd = (buf[4] << 8) | buf[5];
  const rr =
    ((buf[6] << 8) | buf[7]) +
    ((buf[8] << 8) | buf[9]) +
    ((buf[10] << 8) | buf[11]);
  let off = 12;

  for (let i = 0; i < qd; i++) {
    off = skipName(buf, off);
    if (off < 0) return false;
    off += 4;
  }

  for (let i = 0; i < rr; i++) {
    off = skipName(buf, off);
    if (off < 0 || off + 10 > buf.length) return false;
    const type = (buf[off] << 8) | buf[off + 1];
    const rdlen = (buf[off + 8] << 8) | buf[off + 9];
    if (type === 41) {
      // OPT TTL = ext-rcode(8) version(8) flags(16); DO is the high bit of
      // the flags, i.e. the third TTL byte.
      return (buf[off + 6] & 0x80) !== 0;
    }
    off += 10 + rdlen;
    if (off > buf.length) return false;
  }
  return false;
}

/** @param {Uint8Array} buf @param {number} off @returns {number} */
function skipName(buf, off) {
  let jumps = 0;
  while (off < buf.length) {
    const len = buf[off];
    if (len === 0) return off + 1;
    if ((len & 0xc0) === 0xc0) return off + 2;
    off += 1 + len;
    if (++jumps > 255) return -1;
  }
  return -1;
}

/** @param {string} str @returns {Buf|null} */
export function base64urlDecode(str) {
  try {
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    const bin = atob(padded);
    const out = new Buf(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}
