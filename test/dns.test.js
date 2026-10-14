// test/dns.test.js — DNS wire parsing, response builders, TTL, base64url.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  Buf, parseQuestion, buildNxdomainResponse, buildRefusedResponse,
  minTtl, base64urlDecode,
} from '../dns.js';
import { buildQuery, buildResponse, v4rdata } from './helpers.js';

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
  assert.equal(q.name, 'example.com');
});

test('parseQuestion: AAAA + non-IN class pass through', () => {
  const q = parseQuestion(buildQuery('a.b.test', { qtype: 28, qclass: 4 }));
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

test('minTtl: minimum across records, capped at 300', () => {
  const q = buildQuery('a.b');
  const low = buildResponse(q, [{ type: 1, rdata: v4rdata('1.2.3.4'), ttl: 60 }]);
  assert.equal(minTtl(low), 60);

  const capped = buildResponse(q, [{ type: 1, rdata: v4rdata('1.2.3.4'), ttl: 86400 }]);
  assert.equal(minTtl(capped), 300);

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

test('base64urlDecode: round-trip and garbage handling', () => {
  const query = buildQuery('example.com');
  const b64 = Buffer.from(query).toString('base64url');
  const decoded = base64urlDecode(b64);
  assert.deepEqual([...decoded], [...query]);
  assert.equal(base64urlDecode('!!not-base64!!'), null);
});
