// test/dns.test.js — DNS wire parsing, response builders, TTL, base64url.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  Buf, parseQuestion, buildNxdomainResponse, buildRefusedResponse,
  buildBlockedResponse, summariseAnswers, RR,
  minTtl, base64urlDecode, ednsDo,
} from '../dns.js';
import { buildQuery, buildResponse, v4rdata } from './helpers.js';

/** @param {Uint8Array} buf */
const rcode = (buf) => buf[3] & 0x0f;
/** @param {Uint8Array} buf */
const ancount = (buf) => (buf[6] << 8) | buf[7];

test('Buf: BE accessors and construction', () => {
  const b = Buf.from(new Uint8Array([0x12, 0x34, 0x56, 0x78]));
  assert.equal(b.readUInt16BE(0), 0x1234);
  assert.equal(b.readUInt32BE(0), 0x12345678);
  b.writeUInt16BE(0xabcd, 0);
  assert.equal(b[0], 0xab);
  assert.equal(b[1], 0xcd);

  const fromStr = Buf.from('AB');
  assert.equal(fromStr[0], 0x41);
  assert.equal(fromStr.toString(), 'AB');
  assert.ok(Buf.isBuffer(fromStr));
  assert.throws(() => Buf.from({ nope: true }));
});

test('parseQuestion: standard A query', () => {
  const q = parseQuestion(buildQuery('example.com'));
  assert.deepEqual(q, { name: 'example.com', qtype: 1, qclass: 1 });
});

test('parseQuestion: uppercases labels down (case-insensitive QNAME)', () => {
  const q = parseQuestion(buildQuery('EXAMPLE.COM'));
  assert.ok(q, 'parseQuestion returned null');
  assert.equal(q.name, 'example.com');
});

test('parseQuestion: AAAA + non-IN class pass through', () => {
  const q = parseQuestion(buildQuery('a.b.test', { qtype: 28, qclass: 4 }));
  assert.ok(q, 'parseQuestion returned null');
  assert.equal(q.qtype, 28);
  assert.equal(q.qclass, 4);
});

test('parseQuestion: rejects malformed input', () => {
  assert.equal(parseQuestion(null), null);
  assert.equal(parseQuestion(new Uint8Array(5)), null);
  assert.equal(parseQuestion(buildQuery('x.y').slice(0, 20)), null); // truncated
  // label length exceeds remaining bytes
  assert.equal(parseQuestion(Uint8Array.from([0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 65, 97, 0, 0, 1, 0, 1])), null);
});

test('parseQuestion: compression-pointer loops terminate (jumps > 16 -> null)', () => {
  // QNAME starts with a pointer to offset 12 (itself) -> infinite loop guard
  const msg = Uint8Array.from([0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1]);
  assert.equal(parseQuestion(msg), null);
});

test('buildNxdomainResponse: QR set, RCODE=3, counts zeroed, question preserved', () => {
  const query = buildQuery('bad.example');
  const resp = buildNxdomainResponse(query);
  assert.equal(resp[2] & 0x80, 0x80, 'QR bit');
  assert.equal(resp[3] & 0x0f, 3, 'NXDOMAIN rcode');
  assert.equal((resp[6] << 8) | resp[7], 0, 'ANCOUNT');
  assert.deepEqual([...resp.slice(12, query.length)], [...query.slice(12)], 'question bytes intact');
  assert.equal(resp.length, query.length, 'no records appended');
  // query itself untouched (Buf.from copies)
  assert.equal(query[2] & 0x80, 0);
});

test('buildRefusedResponse: RCODE=5', () => {
  const resp = buildRefusedResponse(buildQuery('x.test'));
  assert.equal(resp[3] & 0x0f, 5);
});

test('minTtl: minimum across records, capped at 3600', () => {
  const q = buildQuery('a.b');
  const low = buildResponse(q, [{ type: 1, rdata: v4rdata('1.2.3.4'), ttl: 60 }]);
  assert.equal(minTtl(low), 60);

  const capped = buildResponse(q, [{ type: 1, rdata: v4rdata('1.2.3.4'), ttl: 86400 }]);
  assert.equal(minTtl(capped), 3600);

  const mixed = buildResponse(q, [
    { type: 1, rdata: v4rdata('1.2.3.4'), ttl: 600 },
    { type: 5, rdata: [3, 97, 98, 99, 0], ttl: 120 }, // CNAME, smaller
  ]);
  assert.equal(minTtl(mixed), 120);
});

test('minTtl: degenerate inputs fall back to 60', () => {
  assert.equal(minTtl(null), 60);
  assert.equal(minTtl(new Uint8Array(4)), 60);
  const noAnswers = buildResponse(buildQuery('a.b'), []);
  assert.equal(minTtl(noAnswers), 60);
});

test('ednsDo: true only with an OPT record carrying the DO bit', () => {
  /** Append an OPT RR (payload 1232) with DO on or off. */
  /** @param {Uint8Array} query @param {boolean} doBit */
  const withOpt = (query, doBit) => {
    const out = [...query];
    out[10] = 0;
    out[11] = 1; // ARCOUNT = 1
    out.push(
      0,          // root NAME
      0x00, 0x29, // TYPE = OPT (41)
      0x04, 0xd0, // CLASS = payload size 1232
      0, 0, doBit ? 0x80 : 0, 0, // TTL: ext-rcode, version, flags (DO bit), 0
      0, 0,        // RDLEN = 0
    );
    return Uint8Array.from(out);
  };

  assert.equal(ednsDo(buildQuery('a.b')), false, 'no EDNS at all');
  assert.equal(ednsDo(withOpt(buildQuery('a.b'), false)), false, 'OPT present, DO clear');
  assert.equal(ednsDo(withOpt(buildQuery('a.b'), true)), true, 'OPT present, DO set');
  assert.equal(ednsDo(new Uint8Array(0)), false, 'degenerate input');
});

test('base64urlDecode: round-trip and garbage handling', () => {
  const query = buildQuery('example.com');
  const b64 = Buffer.from(query).toString('base64url');
  const decoded = base64urlDecode(b64);
  assert.ok(decoded, 'base64urlDecode returned null');
  assert.deepEqual([...decoded], [...query]);
  assert.equal(base64urlDecode('!!not-base64!!'), null);
});

test('buildBlockedResponse: default is NXDOMAIN, question echoed intact', () => {
  const query = buildQuery('ads.blocked');
  const resp = buildBlockedResponse(query);
  assert.equal(resp[2] & 0x80, 0x80, 'QR bit');
  assert.equal(resp[3] & 0x0f, 3, 'NXDOMAIN rcode');
  assert.equal(ancount(resp), 0);
  assert.deepEqual([...resp.slice(12, query.length)], [...query.slice(12)], 'question preserved');
});

test('buildBlockedResponse: refused and nodata shapes', () => {
  const refused = buildBlockedResponse(buildQuery('x.test'), 'refused');
  assert.equal(rcode(refused), 5);
  assert.equal(ancount(refused), 0);

  const nodata = buildBlockedResponse(buildQuery('x.test'), 'nodata');
  assert.equal(rcode(nodata), 0, 'NODATA is NOERROR');
  assert.equal(nodata[2] & 0x04, 0x04, 'AA bit set');
  assert.equal(ancount(nodata), 0);

  assert.equal(buildBlockedResponse(buildQuery('x.test'), 'bogus')[3] & 0x0f, 3, 'unknown type -> NXDOMAIN');
});

test('buildBlockedResponse: null_ip answers A with 0.0.0.0, AAAA with ::', () => {
  const a = buildBlockedResponse(buildQuery('null.blocked', { qtype: RR.A }), 'null_ip');
  assert.equal(a[2] & 0x80, 0x80);
  assert.equal(ancount(a), 1);
  const sa = summariseAnswers(a);
  assert.ok(sa, 'summariseAnswers parsed the null answer');
  assert.equal(sa.rcode, 0);
  assert.equal(sa.count, 1);
  assert.equal(sa.sample, '0.0.0.0');

  const aaaa = buildBlockedResponse(buildQuery('null.blocked', { qtype: RR.AAAA }), 'null_ip');
  const sa6 = summariseAnswers(aaaa);
  assert.ok(sa6, 'summariseAnswers parsed the null AAAA answer');
  assert.equal(sa6.count, 1);
  assert.equal(sa6.sample, '0:0:0:0:0:0:0:0');
});

test('buildBlockedResponse: a truncated query degrades to REFUSED instead of a broken answer', () => {
  const junk = new Uint8Array(5); // no complete header, let alone a question
  assert.equal(buildBlockedResponse(junk, 'nodata')[3] & 0x0f, 5);
  assert.equal(buildBlockedResponse(junk, 'null_ip')[3] & 0x0f, 5);
  assert.equal(buildBlockedResponse(junk, 'refused')[3] & 0x0f, 5);
});
