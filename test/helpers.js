// test/helpers.js — Fake KV / env and synthetic DNS wire messages.
import { TextEncoder } from 'node:util';

/** Map-backed Workers KV stand-in with failure injection and op counters. */
export class FakeKV {
  /** @param {Record<string, string>} [initial] */
  constructor(initial = {}) {
    /** @type {Map<string, string>} */
    this.data = new Map(Object.entries(initial));
    this.stats = { gets: 0, puts: 0, lists: 0 };
    this.fail = { get: false, put: false, list: false };
  }

  /**
   * @param {string} key
   * @param {'text'|'json'} [type]
   * @returns {Promise<any>}
   */
  async get(key, type) {
    this.stats.gets++;
    if (this.fail.get) throw new Error('kv get failed (injected)');
    const v = this.data.get(key);
    if (v === undefined) return null;
    return type === 'json' ? JSON.parse(v) : v;
  }

  /** @param {string} key @param {string} value */
  async put(key, value) {
    this.stats.puts++;
    if (this.fail.put) throw new Error('kv put failed (injected)');
    this.data.set(key, String(value));
  }

  /** @param {string} key */
  async delete(key) {
    this.data.delete(key);
  }

  /** @param {{prefix?: string, cursor?: string}} [opts] */
  async list({ prefix = '', cursor } = {}) {
    this.stats.lists++;
    if (this.fail.list) throw new Error('kv list failed (injected)');
    if (cursor) throw new Error('FakeKV does not paginate');
    const keys = [...this.data.keys()]
      .filter((k) => k.startsWith(prefix))
      .map((name) => ({ name }));
    return { keys, list_complete: true, cursor: null };
  }
}

const enc = new TextEncoder();
/** @param {string} s @returns {number[]} */
const bytes = (s) => [...enc.encode(s)];

/**
 * Build a raw DNS query message.
 * @param {string} name QNAME
 * @param {{qtype?:number, qclass?:number, id?:number, rd?:boolean}} [opts]
 * @returns {Uint8Array}
 */
export function buildQuery(name, opts = {}) {
  const { qtype = 1, qclass = 1, id = 0x1234, rd = true } = opts;
  const qname = [];
  for (const label of name.split('.').filter(Boolean)) {
    qname.push(label.length, ...bytes(label));
  }
  qname.push(0);
  const flags = rd ? 0x0100 : 0x0000;
  const head = [
    (id >> 8) & 0xff, id & 0xff,
    (flags >> 8) & 0xff, flags & 0xff,
    0, 1, // QDCOUNT
    0, 0, // ANCOUNT
    0, 0, // NSCOUNT
    0, 0, // ARCOUNT
  ];
  const tail = [(qtype >> 8) & 0xff, qtype & 0xff, (qclass >> 8) & 0xff, qclass & 0xff];
  return new Uint8Array([...head, ...qname, ...tail]);
}

/**
 * Build a response message; names are compressed as a pointer to byte 12 (the
 * question's QNAME start), valid while `query` starts with the standard
 * 12-byte header. `rcode` lets a test answer SERVFAIL/NXDOMAIN.
 * @param {Uint8Array} query
 * @param {Array<{type:number, rdata:number[], ttl?:number}>} records
 * @param {number} [rcode]
 * @returns {Uint8Array}
 */
export function buildResponse(query, records, rcode = 0) {
  const out = [...query];
  // QR=1, keep RD, requested RCODE
  out[2] = out[2] | 0x80;
  out[3] = (out[3] & 0xf0) | (rcode & 0x0f);
  out[6] = (records.length >> 8) & 0xff;
  out[7] = records.length & 0xff;
  for (const r of records) {
    const ttl = r.ttl ?? 300;
    out.push(
      0xc0, 0x0c,                      // compressed name -> offset 12
      (r.type >> 8) & 0xff, r.type & 0xff,
      0, 1,                            // class IN
      (ttl >>> 24) & 0xff, (ttl >>> 16) & 0xff, (ttl >>> 8) & 0xff, ttl & 0xff,
      (r.rdata.length >> 8) & 0xff, r.rdata.length & 0xff,
      ...r.rdata,
    );
  }
  return new Uint8Array(out);
}

/** IPv4 dotted quad -> 4-byte rdata array.
 * @param {string} ip
 * @returns {number[]}
 */
export function v4rdata(ip) {
  return ip.split('.').map((n) => parseInt(n, 10) & 0xff);
}

/** Expand an IPv6 literal to a 16-byte rdata array (supports :: and ::ffff:x).
 * @param {string} ip
 * @returns {number[]}
 */
export function v6rdata(ip) {
  const [head, tail] = ip.split('::');
  const h = head ? head.split(':').filter(Boolean) : [];
  const t = tail !== undefined ? tail.split(':').filter(Boolean) : [];
  /** @param {string} part @returns {number[]|null} */
  const expandV4 = (part) => {
    const m = part.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (!m) return null;
    const a = m.slice(1).map(Number);
    return [(a[0] << 8) | a[1], (a[2] << 8) | a[3]];
  };
  /** @param {string[]} parts @returns {number[]} */
  const toWords = (parts) => {
    const out = [];
    for (const p of parts) {
      const v4 = expandV4(p);
      if (v4) out.push(...v4);
      else out.push(parseInt(p, 16));
    }
    return out;
  };
  const hw = toWords(h);
  const tw = tail === undefined ? [] : toWords(t);
  const fill = 8 - hw.length - tw.length;
  if (fill < 0) throw new Error('bad ipv6: ' + ip);
  const words = tail === undefined ? [...hw, ...Array(8 - hw.length).fill(0)] : [...hw, ...Array(fill).fill(0), ...tw];
  const out = [];
  for (const w of words) out.push((w >> 8) & 0xff, w & 0xff);
  return out;
}
