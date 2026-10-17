// test/filters.test.js — query decision chain + answer-level rebinding.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  runQueryFilters, rebindNameHit, idnHit, tldOf,
  isPrivateV4, isPrivateV6, privateAnswerIP,
} from '../filters.js';
import { buildQuery, buildResponse, v4rdata, v6rdata } from './helpers.js';

// ---- fixtures ----------------------------------------------------------------

const ON = { rebindProtection: true, idnBlock: true, tldBlock: true, keywordBlock: true };
const OFF = { rebindProtection: false, idnBlock: false, tldBlock: false, keywordBlock: false };

/**
 * @param {{rules?: Array<[string, 'allow'|'deny']>, block?: string[], keywords?: string[], tlds?: string[]}} [o]
 * @returns {{ruleStore: {match(name: string): {kind:'allow'|'deny', at:string}|null}, blocklist: {match(name: string): string|null}, keywordStore: {get(): Set<string>}, tldStore: {get(): Set<string>}}}
 */
function mkStores({ rules = [], block = [], keywords = [], tlds = [] } = {}) {
  const ruleMap = new Map(rules);
  const blockSet = new Set(block);
  return {
    ruleStore: {
      match(name) {
        // walk parents like the real store (allow > deny)
        /** @type {{kind:'deny', at:string}|null} */
        let deny = null;
        for (let d = name; ;) {
          const hit = ruleMap.get(d);
          if (hit === 'allow') return { kind: 'allow', at: d };
          if (hit === 'deny' && !deny) deny = { kind: 'deny', at: d };
          const dot = d.indexOf('.');
          if (dot === -1) break;
          d = d.slice(dot + 1);
        }
        return deny;
      },
    },
    blocklist: {
      match(name) {
        for (let d = name; ;) {
          if (blockSet.has(d)) return d;
          const dot = d.indexOf('.');
          if (dot === -1) return null;
          d = d.slice(dot + 1);
          if (d.indexOf('.') === -1) return blockSet.has(d) ? d : null;
        }
      },
    },
    keywordStore: { get: () => new Set(keywords) },
    tldStore: { get: () => new Set(tlds) },
  };
}

// ---- tld / rebinding / idn helpers -------------------------------------------

test('tldOf: last label of dotted names, empty when single label', () => {
  assert.equal(tldOf('a.example.com'), 'com');
  assert.equal(tldOf('localhost'), '', 'label-only by design; rebindNameHit handles bare names');
  assert.equal(tldOf(''), '');
});

test('rebindNameHit: special-use names and internal TLDs', () => {
  assert.equal(rebindNameHit('localhost'), 'localhost');
  assert.equal(rebindNameHit('printer.local'), 'local');
  assert.equal(rebindNameHit('router.lan'), 'lan');
  assert.equal(rebindNameHit('nas.home.arpa'), 'home.arpa');
  assert.equal(rebindNameHit('db.internal'), 'internal');
  assert.equal(rebindNameHit('anything.test'), 'test');
  assert.equal(rebindNameHit('example.com'), null);
  assert.equal(rebindNameHit('prefixlocalhost.evil.com'), null, 'substring must not match');
  assert.equal(rebindNameHit('a.localhost.evil.com'), null, 'mid-name .localhost must not match');
});

test('idnHit: punycode anywhere, non-ascii bytes, clean ascii', () => {
  assert.equal(idnHit('xn--pple-43d.com'), 'xn--pple-43d');
  assert.equal(idnHit('a.xn--80ak6aa92e.com'), 'xn--80ak6aa92e');
  assert.equal(idnHit('example.com'), null);
  // raw UTF-8 bytes in a label (non-compliant client) -> flagged
  assert.equal(idnHit('раypal.com'), '<non-ascii>');
});

// ---- runQueryFilters precedence ----------------------------------------------

test('precedence: allow beats deny, blocklist, and every policy', () => {
  const s = mkStores({
    rules: [['example.com', 'allow']],
    block: ['example.com'],
    keywords: ['sub'],
    tlds: ['com'],
  });
  const v = runQueryFilters(s, ON, 'sub.example.com');
  assert.deepEqual(v, { status: 'allow', filter: 'allowlist', matched: 'example.com' });
});

test('precedence: deny beats blocklist', () => {
  const s = mkStores({ rules: [['example.com', 'deny']], block: ['example.com'] });
  const v = runQueryFilters(s, ON, 'www.example.com');
  assert.equal(v.status, 'deny');
  assert.equal(v.filter, 'denylist');
});

test('precedence: blocklist beats tld/keyword/rebind/idn', () => {
  const s = mkStores({
    block: ['tracker.zip'],
    keywords: ['tracker'],
    tlds: ['zip'],
  });
  // 'local' is both internal-TLD and part of the name; blocklist must win
  const v = runQueryFilters(s, ON, 'tracker.zip');
  assert.equal(v.status, 'blocklist');
  const s2 = mkStores({ block: ['evil.local'], tlds: ['zip'], keywords: ['evil'] });
  const v2 = runQueryFilters(s2, ON, 'evil.local');
  assert.equal(v2.status, 'blocklist');
});

test('precedence: tld beats keyword beats rebinding beats idn', () => {
  const s = mkStores({ keywords: ['xn--'], tlds: ['zip'] });
  const v = runQueryFilters(s, ON, 'xn--bad.zip');
  assert.equal(v.status, 'tld', 'tld wins over keyword/rebind/idn');

  const s2 = mkStores({ keywords: ['xn--'] });
  const v2 = runQueryFilters(s2, ON, 'xn--bad.com');
  assert.equal(v2.status, 'keyword', 'keyword wins over idn');

  const s3 = mkStores();
  const v3 = runQueryFilters(s3, ON, 'xn--evil.local');
  assert.equal(v3.status, 'rebind', 'rebind wins over idn (.local is both)');
});

test('toggles off: each policy layer is inert', () => {
  const s = mkStores({ keywords: ['doubleclick'], tlds: ['zip'] });
  assert.deepEqual(runQueryFilters(s, OFF, 'a.doubleclick.zip'), { status: 'none', filter: 'upstream', matched: null });
  assert.equal(runQueryFilters(s, { ...ON, tldBlock: false }, 'doubleclick.zip').status, 'keyword',
    'tld disabled -> keyword catches it');
  assert.equal(runQueryFilters(s, { ...ON, keywordBlock: false }, 'a.doubleclick.com').status, 'none');
  assert.equal(runQueryFilters(s, { ...ON, rebindProtection: false }, 'x.local').status, 'none');
  assert.equal(runQueryFilters(s, { ...ON, idnBlock: false }, 'xn--a.com').status, 'none');
});

test('empty lists: no accidental matches', () => {
  const s = mkStores();
  assert.equal(runQueryFilters(s, ON, 'anything.example.com').status, 'none');
  assert.equal(runQueryFilters(s, ON, 'x.zip').status, 'none');
});

test('deny is reported with the matched parent rule', () => {
  const s = mkStores({ rules: [['example.com', 'deny']] });
  const v = runQueryFilters(s, ON, 'cdn.sub.example.com');
  assert.deepEqual(v, { status: 'deny', filter: 'denylist', matched: 'example.com' });
});

// ---- private address classification ------------------------------------------

/**
 * @param {string} ip
 * @param {boolean} expect
 * @param {string} [msg]
 */
function v4ok(ip, expect, msg) {
  assert.equal(isPrivateV4(Uint8Array.from(v4rdata(ip)), 0), expect, msg ? `${ip} (${msg})` : ip);
}

test('isPrivateV4: boundaries of every covered range', () => {
  v4ok('9.255.255.255', false);
  v4ok('10.0.0.0', true);
  v4ok('10.255.255.255', true);
  v4ok('11.0.0.1', false);
  v4ok('172.15.255.255', false);
  v4ok('172.16.0.1', true);
  v4ok('172.31.255.255', true);
  v4ok('172.32.0.1', false);
  v4ok('192.167.255.255', false);
  v4ok('192.168.1.1', true);
  v4ok('192.169.0.1', false);
  v4ok('169.253.255.255', false);
  v4ok('169.254.169.254', true, 'cloud metadata');
  v4ok('169.255.0.1', false);
  v4ok('100.63.255.255', false);
  v4ok('100.64.0.1', true);
  v4ok('100.127.255.255', true);
  v4ok('100.128.0.1', false);
  v4ok('127.0.0.1', true);
  v4ok('128.0.0.1', false);
  v4ok('0.0.0.0', true);
  v4ok('8.8.8.8', false);
});

test('isPrivateV6: loopback, ULA, link-local, v4-mapped', () => {
  /** @param {string} ip @returns {boolean} */
  const w = (ip) => isPrivateV6(Uint8Array.from(v6rdata(ip)), 0);
  assert.equal(w('::'), true);
  assert.equal(w('::1'), true);
  assert.equal(w('fc00::1'), true);
  assert.equal(w('fd12:3456::1'), true);
  assert.equal(w('fe80::1'), true);
  assert.equal(w('febf::1'), true, 'fe80::/10 upper edge');
  assert.equal(w('fec0::1'), false, 'site-local is NOT blocked');
  assert.equal(w('2001:4860:4860::8888'), false);
  assert.equal(w('::ffff:192.168.1.1'), true, 'v4-mapped private');
  assert.equal(w('::ffff:8.8.8.8'), false, 'v4-mapped public');
});

// ---- privateAnswerIP over synthetic wire messages ----------------------------

test('privateAnswerIP: public A -> null', () => {
  const resp = buildResponse(buildQuery('ok.example'), [{ type: 1, rdata: v4rdata('93.184.216.34') }]);
  assert.equal(privateAnswerIP(resp), null);
});

test('privateAnswerIP: private A -> dotted quad', () => {
  const resp = buildResponse(buildQuery('evil.example'), [{ type: 1, rdata: v4rdata('10.0.0.5') }]);
  assert.equal(privateAnswerIP(resp), '10.0.0.5');
});

test('privateAnswerIP: finds private record after a public one', () => {
  const resp = buildResponse(buildQuery('mix.example'), [
    { type: 1, rdata: v4rdata('1.1.1.1') },
    { type: 1, rdata: v4rdata('192.168.0.10') },
  ]);
  assert.equal(privateAnswerIP(resp), '192.168.0.10');
});

test('privateAnswerIP: private AAAA -> marker', () => {
  const resp = buildResponse(buildQuery('v6.example'), [{ type: 28, rdata: v6rdata('fd00::1') }]);
  assert.equal(privateAnswerIP(resp), '<private-v6>');
  const ok = buildResponse(buildQuery('v6.example'), [{ type: 28, rdata: v6rdata('2606:4700:4700::1111') }]);
  assert.equal(privateAnswerIP(ok), null);
});

test('privateAnswerIP: non-address record types are ignored', () => {
  // TXT record whose bytes happen to look like 10.0.0.1
  const resp = buildResponse(buildQuery('txt.example'), [{ type: 16, rdata: [4, 10, 0, 0, 1] }]);
  assert.equal(privateAnswerIP(resp), null);
});

test('privateAnswerIP: degenerate buffers -> null', () => {
  assert.equal(privateAnswerIP(null), null);
  assert.equal(privateAnswerIP(new Uint8Array(4)), null);
  const q = buildQuery('a.b');
  assert.equal(privateAnswerIP(q), null, 'query with no answers');
  assert.equal(privateAnswerIP(q.slice(0, 30)), null, 'truncated answer -> null');
});
