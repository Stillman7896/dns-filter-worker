
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
    throw new Error('unsupported');
  }
  static isBuffer(x) {
    return x instanceof Uint8Array;
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
  toString(enc, s, e) {
    s = s ?? 0;
    e = e ?? this.length;
    let out = '';
    for (let i = s; i < e; i++) out += String.fromCharCode(this[i]);
    return out;
  }
}

const Buffer = {
  from: Buf.from,
  isBuffer: Buf.isBuffer,
};
