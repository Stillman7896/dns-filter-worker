// idn.js — punycode translation: rule normalization and the probe API both
// depend on it, so decode is cross-checked against node:punycode where that
// reference implementation still agrees with us.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toAscii, toUnicode, punycodeDecode } from '../idn.js';

test('toAscii: foreign characters become the A-label the resolver sees', () => {
  assert.equal(toAscii('bücher.de'), 'xn--bcher-kva.de');
  assert.equal(toAscii('例子.中国'), 'xn--fsqu00a.xn--fiqs8s');
  assert.equal(toAscii('вася.рф'), 'xn--80ad0c0c.xn--p1ai');
  assert.equal(toAscii('日本語.jp。'), 'xn--wgv71a119e.jp', 'ideographic dot maps to "."');
  assert.equal(toAscii('STRASSE.DE'), 'strasse.de', 'UTS-46 folds case');
  assert.equal(toAscii('Ω.example'), 'xn--bya.example');
});

test('toAscii: ASCII passes through, junk is rejected', () => {
  assert.equal(toAscii('sub.example.com'), 'sub.example.com');
  assert.equal(toAscii('example.com.'), 'example.com');
  assert.equal(toAscii(''), '');
  assert.equal(toAscii(/** @type {any} */ (null)), '');
  assert.equal(toAscii('a b.com'), '', 'space is not a host');
  assert.equal(toAscii('💥'), 'xn--hs8h', 'emoji still gets a legal label');
});

test('toUnicode: A-labels decode back to the script they came from', () => {
  assert.equal(toUnicode('xn--bcher-kva.de'), 'bücher.de');
  assert.equal(toUnicode('xn--80ad0c0c.xn--p1ai'), 'вася.рф');
  assert.equal(toUnicode('xn--fsqu00a.xn--fiqs8s'), '例子.中国');
  assert.equal(toUnicode('sub.example.com'), 'sub.example.com', 'ASCII untouched');
  assert.equal(toUnicode('xn--hs8h.com'), '💥.com');
});

test('toUnicode: malformed labels stay as they are instead of throwing', () => {
  assert.equal(toUnicode('xn--z.com'), 'xn--z.com', 'not decodable');
  assert.equal(toUnicode('xn--.com'), 'xn--.com');
  assert.equal(toUnicode(/** @type {any} */ (undefined)), '');
});

test('punycodeDecode: agrees with the reference decoder', async () => {
  const { default: ref } = await import('node:punycode');
  const labels = [
    'xn--bcher-kva', 'xn--80ad0c0c', 'xn--fsqu00a', 'xn--fa-hia',
    'xn--bya', 'xn--9q8h', 'xn--80ak6aa92e', 'xn--wgv71a119e',
  ];
  for (const label of labels) {
    assert.equal(punycodeDecode(label.slice(4)), ref.toUnicode(label), label);
  }
});

test('punycodeDecode: rejects payloads that are not really punycode', () => {
  assert.equal(punycodeDecode(''), '', 'empty payload decodes to nothing');
  assert.throws(() => punycodeDecode('é-z'), /ascii/, 'non-ascii in the literal half');
  assert.throws(() => punycodeDecode('é'), /digit/);
  assert.throws(() => punycodeDecode('zz'), /truncated/);
  assert.throws(() => punycodeDecode('a!b'), /digit/);
  assert.throws(() => punycodeDecode('a'.repeat(60)), /too long/, 'over 63 bytes with xn--');
});

test('toAscii then toUnicode round-trips an internationalized name', () => {
  for (const name of ['bücher.de', 'вася.рф', '例子.中国', 'faß.de', 'münchen.de']) {
    assert.equal(toUnicode(toAscii(name)), name, name);
  }
});
