// test/odoh.test.js — HPKE base mode against RFC 9180 A.1 vectors, plus a full
// Oblivious DoH exchange (RFC 9230) between this module's client half and a
// target half assembled from the same primitives.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SUITE, aeadOpen, aeadSeal, clearConfigCache, concat, contextExport, decodeMessage,
  decodePlaintext, encodeMessage, encodePlaintext, expandRelayTemplate, fetchOdohConfig,
  fromHex, hkdfExpand, hkdfExtract, nonceFor, odohKeyId, parseOdohConfigs,
  prepareOdohQuery, queryAad, responseAad, setupBaseR, setupBaseS, toHex, x25519PublicKey,
} from '../odoh.js';
import { buildQuery, buildResponse, v4rdata } from './helpers.js';

const utf8 = (/** @type {string} */ s) => new TextEncoder().encode(s);

// ---- RFC 9180 A.1.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM ----

const V = {
  info: fromHex('4f6465206f6e2061204772656369616e2055726e'),
  skEm: fromHex('52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736'),
  pkEm: fromHex('37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431'),
  pkRm: fromHex('3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d'),
  skRm: fromHex('4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8'),
  key: '4531685d41d65f03dc48f6b8302c05b0',
  baseNonce: '56d890e5accaaf011cff4b7d',
  exporter: '45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8',
  pt: fromHex('4265617574792069732074727574682c20747275746820626561757479'),
};

test('hkdf: RFC 5869 A.1 extract + expand vectors', async () => {
  const prk = await hkdfExtract(fromHex('000102030405060708090a0b0c'), fromHex('0b'.repeat(22)));
  assert.equal(toHex(prk), '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
  const okm = await hkdfExpand(prk, fromHex('f0f1f2f3f4f5f6f7f8f9'), 42);
  assert.equal(toHex(okm), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
});

test('hpke: SetupBaseS matches the RFC 9180 A.1.1 key schedule', async () => {
  const ctx = await setupBaseS(V.pkRm, V.info, V.skEm);
  assert.equal(toHex(ctx.enc), toHex(V.pkEm), 'enc = pk(skE)');
  assert.equal(toHex(ctx.key), V.key);
  assert.equal(toHex(ctx.baseNonce), V.baseNonce);
  assert.equal(toHex(ctx.exporterSecret), V.exporter);

  // exporter_context = "" -> the RFC's first exported value
  const exported = await contextExport(ctx.exporterSecret, new Uint8Array(0), 32);
  assert.equal(toHex(exported), '3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee');
});

test('hpke: seq 0 / seq 1 ciphertexts and the nonce XOR', async () => {
  const ctx = await setupBaseS(V.pkRm, V.info, V.skEm);

  const ct0 = await aeadSeal(ctx.key, nonceFor(ctx.baseNonce, 0), fromHex('436f756e742d30'), V.pt);
  assert.equal(
    toHex(ct0),
    'f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a',
  );
  assert.equal(toHex(nonceFor(ctx.baseNonce, 1)), '56d890e5accaaf011cff4b7c', 'seq 1 flips the last byte');
  const ct1 = await aeadSeal(ctx.key, nonceFor(ctx.baseNonce, 1), fromHex('436f756e742d31'), V.pt);
  assert.equal(
    toHex(ct1),
    'af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84',
  );
  assert.equal(toHex(nonceFor(ctx.baseNonce, 256)), '56d890e5accaaf011cff4a7d', 'carry into the second byte');

  // The recipient derives the same schedule and opens what the sender sealed.
  const recv = await setupBaseR(ctx.enc, V.skRm, V.info, V.pkRm);
  const opened = await aeadOpen(recv.key, nonceFor(recv.baseNonce, 0), fromHex('436f756e742d30'), ct0);
  assert.equal(toHex(opened), toHex(V.pt));
});

// ---- ODoH config parsing (RFC 9230 §5) ----

// Captured from https://odoh.cloudflare-dns.com/.well-known/odohconfigs.
const CLOUDFLARE_CONFIG = fromHex(
  '002c000100280020000100010020697f0ab420e7be549bef51d1eedaaaff593d1f400d19da5b8b14bdbab030ac8865',
);

test('odoh: parses a real target config and skips unsupported ones', () => {
  const config = parseOdohConfigs(CLOUDFLARE_CONFIG);
  assert.ok(config, 'Cloudflare config should parse');
  assert.equal(config.kemId, SUITE.kemId);
  assert.equal(config.kdfId, SUITE.kdfId);
  assert.equal(config.aeadId, SUITE.aeadId);
  assert.equal(config.publicKey.length, 32);
  assert.equal(config.contents.length, 40);

  // version 0x0002 -> unsupported; truncated blobs -> null
  assert.equal(parseOdohConfigs(fromHex('000e0002000a0020000100010020' + '00'.repeat(32))), null);
  assert.equal(parseOdohConfigs(new Uint8Array(3)), null);
});

test('odoh: message + plaintext framing round-trips, padding must be zero', () => {
  const dns = buildQuery('framing.test');
  const plain = encodePlaintext(dns);
  assert.deepEqual([.../** @type {Uint8Array} */ (decodePlaintext(plain))], [...dns]);

  const padded = concat([encodePlaintext(dns), Uint8Array.of(0, 0, 0)]);
  assert.deepEqual([.../** @type {Uint8Array} */ (decodePlaintext(padded))], [...dns], 'zero padding is accepted');

  assert.equal(decodePlaintext(concat([encodePlaintext(dns), Uint8Array.of(1)])), null, 'non-zero padding');
  assert.equal(decodePlaintext(Uint8Array.of(0, 9, 1)), null, 'truncated message');

  const keyId = new Uint8Array(32).fill(7);
  const body = encodeMessage(0x01, keyId, plain);
  const decoded = decodeMessage(body);
  assert.ok(decoded, 'message decodes');
  assert.equal(decoded.messageType, 0x01);
  assert.deepEqual([...decoded.keyId], [...keyId]);
  assert.deepEqual([...decoded.encrypted], [...plain]);
  assert.equal(decodeMessage(Uint8Array.of(1, 0, 8)), null, 'short body');
});

// ---- relay templates (RFC 9230 §4.1) ----

test('odoh: relay templates accept only targethost + targetpath over https', () => {
  assert.equal(
    expandRelayTemplate('https://relay.example/proxy{?targethost,targetpath}', 'odoh.cloudflare-dns.com', '/dns-query'),
    'https://relay.example/proxy?targethost=odoh.cloudflare-dns.com&targetpath=%2Fdns-query',
  );
  assert.equal(expandRelayTemplate('http://relay.example/proxy{?targethost,targetpath}', 'a.example', '/dns-query'), null, 'plain http');
  assert.equal(expandRelayTemplate('https://relay.example/proxy', 'a.example', '/dns-query'), null, 'no variables');
  assert.equal(expandRelayTemplate('https://relay.example/{?targethost,targetpath,extra}', 'a.example', '/dns-query'), null, 'extra variable');
  assert.equal(
    expandRelayTemplate('https://relay.example/{?targethost,targetpath}{?targethost,targetpath}', 'a.example', '/dns-query'),
    null,
    'duplicate template',
  );
});

// ---- full exchange: client half here, target half from the same primitives ----

/**
 * A minimal ODoH target: decrypt a query and seal a response, following
 * RFC 9230 §8.
 * @param {Uint8Array} skR
 */
async function target(skR) {
  const pkR = await x25519PublicKey(skR);
  const contents = concat([Uint8Array.of(0x00, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x20), pkR]);
  return {
    pkR,
    config: { kemId: SUITE.kemId, kdfId: SUITE.kdfId, aeadId: SUITE.aeadId, publicKey: pkR, contents },
    /**
     * @param {Uint8Array} body
     * @param {(query: Uint8Array) => Uint8Array} answer
     */
    async handle(body, answer) {
      const request = decodeMessage(body);
      assert.ok(request, 'relay body is a valid message');
      assert.equal(request.messageType, 0x01);
      const enc = request.encrypted.subarray(0, 32);
      const context = await setupBaseR(enc, skR, utf8('odoh query'), pkR);
      const plain = await aeadOpen(context.key, context.baseNonce, queryAad(request.keyId), request.encrypted.subarray(32));
      const query = /** @type {Uint8Array} */ (decodePlaintext(plain));
      const dnsResponse = answer(query);

      const respNonce = new Uint8Array(16).fill(0x11);
      const exported = await contextExport(context.exporterSecret, utf8('odoh response'), 16);
      const prk = await hkdfExtract(concat([plain, Uint8Array.of(0, respNonce.length), respNonce]), exported);
      const respKey = await hkdfExpand(prk, utf8('odoh key'), 16);
      const respIv = await hkdfExpand(prk, utf8('odoh nonce'), 12);
      const sealed = await aeadSeal(respKey, respIv, responseAad(respNonce), encodePlaintext(dnsResponse));
      return { query, reply: encodeMessage(0x02, respNonce, sealed), respNonce };
    },
  };
}

test('odoh: query encrypts, target decrypts, response comes back readable', async () => {
  const server = await target(new Uint8Array(32).fill(0x5a));
  const query = buildQuery('odoh.example.com');
  const prepared = await prepareOdohQuery(
    'https://odoh.cloudflare-dns.com/dns-query',
    'https://relay.example/proxy{?targethost,targetpath}',
    query,
    { config: server.config },
  );
  assert.equal(prepared.url, 'https://relay.example/proxy?targethost=odoh.cloudflare-dns.com&targetpath=%2Fdns-query');
  assert.equal(prepared.contentType, 'application/oblivious-dns-message');

  const keyId = await odohKeyId(server.config.contents);
  const request = /** @type {NonNullable<ReturnType<typeof decodeMessage>>} */ (decodeMessage(prepared.body));
  assert.deepEqual([...request.keyId], [...keyId], 'key id names the config used');

  const expected = buildResponse(query, [{ type: 1, rdata: v4rdata('203.0.113.7') }]);
  const { query: seen, reply } = await server.handle(prepared.body, () => expected);
  assert.deepEqual([...seen], [...query], 'target recovered the DNS query');
  assert.deepEqual([...await prepared.decrypt(reply)], [...expected], 'client recovered the DNS response');
});

test('odoh: decrypt rejects an unknown nonce, a wrong type and bad padding', async () => {
  const server = await target(new Uint8Array(32).fill(0x33));
  const prepared = await prepareOdohQuery(
    'https://odoh.example/dns-query',
    'https://relay.example/proxy{?targethost,targetpath}',
    buildQuery('x.example'),
    { config: server.config },
  );
  const { reply } = await server.handle(prepared.body, () => buildResponse(buildQuery('x.example'), []));

  const swapped = /** @type {NonNullable<ReturnType<typeof decodeMessage>>} */ (decodeMessage(reply));
  const wrongNonce = encodeMessage(0x02, new Uint8Array(16).fill(0x22), swapped.encrypted);
  await assert.rejects(() => prepared.decrypt(wrongNonce), /padding invalid|operation|decrypt/i);

  await assert.rejects(
    () => prepared.decrypt(encodeMessage(0x01, swapped.keyId, swapped.encrypted)),
    /message type/,
  );
  await assert.rejects(() => prepared.decrypt(Uint8Array.of(2, 0)), /malformed/);
});

test('odoh: config is fetched from /.well-known/odohconfigs and cached', async () => {
  clearConfigCache();
  let calls = 0;
  const fetchImpl = /** @type {typeof fetch} */ (async (input) => {
    calls++;
    assert.equal(String(input), 'https://odoh.cache.test/.well-known/odohconfigs');
    return new Response(CLOUDFLARE_CONFIG);
  });

  const first = await fetchOdohConfig('https://odoh.cache.test/dns-query', fetchImpl);
  assert.equal(first.publicKey.length, 32);
  assert.equal(calls, 1);

  await prepareOdohQuery(
    'https://odoh.cache.test/dns-query',
    'https://relay.example/proxy{?targethost,targetpath}',
    buildQuery('cached.example'),
    { fetchImpl },
  );
  assert.equal(calls, 1, 'cached config reused');

  await assert.rejects(
    () => fetchOdohConfig('https://bad.cache.test/dns-query', /** @type {typeof fetch} */ (async () => new Response('nope', { status: 500 }))),
    /odoh config HTTP 500/,
  );
  await assert.rejects(
    () => prepareOdohQuery('https://odoh.example/dns-query', 'https://relay.example/proxy', buildQuery('a.example')),
    /relay must be/,
  );
  clearConfigCache();
});
