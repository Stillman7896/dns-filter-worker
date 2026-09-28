
// ---------- Minimal Buffer shim (Uint8Array + BE accessors) ----------
class Buf extends Uint8Array {
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

  static isBuffer(x) {
    return x instanceof Buf || x instanceof Uint8Array;
  }

  readUInt16BE(o) {
    return (this[o] << 8) | this[o + 1];
  }

  readUInt32BE(o) {
    return (
      this[o] * 0x1000000 +
      ((this[o + 1] << 16) | (this[o + 2] << 8) | this[o + 3])
    );
  }

  writeUInt16BE(v, o) {
    this[o] = (v >>> 8) & 0xff;
    this[o + 1] = v & 0xff;
  }

  writeUInt32BE(v, o) {
    this[o] = (v >>> 24) & 0xff;
    this[o + 1] = (v >>> 16) & 0xff;
    this[o + 2] = (v >>> 8) & 0xff;
    this[o + 3] = v & 0xff;
  }

  toString(_enc, s, e) {
    s = s ?? 0;
    e = e ?? this.length;
    // Fast path for ASCII DNS labels; latin1 is 1 byte per char.
    let out = '';
    for (let i = s; i < e; i++) out += String.fromCharCode(this[i]);
    return out;
  }
}

/** Exposed so the Worker entrypoint can convert ArrayBuffer → Buf. */
export { Buf };

// ---------- DNS message helpers ----------

/**
 * Parse QNAME out of a raw DNS query (wire format).
 * @param {Buf|Uint8Array} buf
 * @returns {{ name: string, qtype: number, qclass: number } | null}
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

    // Compression pointer (0xC0 mask)
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
      // Lowercase ASCII A-Z → a-z inline (avoid .toLowerCase alloc per label).
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

/**
 * Echo the query as an NXDOMAIN response (QR=1, RD preserved, RA=1, RCODE=3).
 * @param {Buf|Uint8Array} queryBuf
 * @returns {Buf}
 */
export function buildNxdomainResponse(queryBuf) {
  const out = Buf.from(queryBuf);
  const flags = out.readUInt16BE(2);
  out.writeUInt16BE(0x8000 | 0x0080 | (flags & 0x0100) | 0x0003, 2);
  out.writeUInt16BE(0, 6); // ANCOUNT
  out.writeUInt16BE(0, 8); // NSCOUNT
  out.writeUInt16BE(0, 10); // ARCOUNT
  return out;
}

/**
 * Echo the query as a REFUSED response (RCODE=5).
 * @param {Buf|Uint8Array} queryBuf
 * @returns {Buf}
 */
export function buildRefusedResponse(queryBuf) {
  const out = Buf.from(queryBuf);
  const flags = out.readUInt16BE(2);
  out.writeUInt16BE(0x8000 | 0x0080 | (flags & 0x0100) | 0x0005, 2);
  out.writeUInt16BE(0, 6);
  out.writeUInt16BE(0, 8);
  out.writeUInt16BE(0, 10);
  return out;
}

/**
 * Minimum TTL across all records in a DNS response (capped at 300s).
 * @param {Buf|Uint8Array} respBuf
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
    const ttl = respBuf.readUInt32BE(off + 4);
    if (ttl < min) min = ttl;
    const rdlen = (respBuf[off + 8] << 8) | respBuf[off + 9];
    off += 10 + rdlen;
    if (off > respBuf.length) return 60;
  }

  if (!Number.isFinite(min) || min <= 0) return 60;
  return Math.min(min, 300);
}

/**
 * Skip a (possibly compressed) DNS name at `off`, returning the offset after it.
 * @returns {number} new offset, or -1 on malformed input
 */
function skipName(buf, off) {
  let jumps = 0;
  while (off < buf.length) {
    const len = buf[off];
    if (len === 0) return off + 1;
    if ((len & 0xc0) === 0xc0) return off + 2; // pointer is 2 bytes
    off += 1 + len;
    if (++jumps > 255) return -1;
  }
  return -1;
}

/**
 * Decode base64url string → Buf. Returns null on failure.
 * @param {string} str
 * @returns {Buf|null}
 */
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
