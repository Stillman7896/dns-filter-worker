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
