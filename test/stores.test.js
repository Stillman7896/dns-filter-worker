// test/stores.test.js — KV blob stores: rules, lists, settings.
// Covers the read-modify-write model, version caching, legacy migration,
// and the "never persist an empty blob over real data" failure guards.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RuleStore, normalizeDomain } from '../rules.js';
import { TextSetStore, normalizeTld, normalizeKeyword, DATA_VERSION_KEY } from '../lists.js';
import { SettingsStore, DEFAULT_SETTINGS, clampRetention } from '../settings.js';
import { FakeKV } from './helpers.js';

const RULES_KEY = 'rules:data';

// ---- RuleStore ----------------------------------------------------------------

test('RuleStore: put/list/delete round-trip through one blob', async () => {
  const kv = new FakeKV();
  const rs = new RuleStore(kv);
  await rs.put('example.com', 'deny');
  await rs.put('ok.example.org', 'allow');

  assert.deepEqual(await rs.list(), [
    { domain: 'example.com', kind: 'deny' },
    { domain: 'ok.example.org', kind: 'allow' },
  ]);
  assert.equal(kv.data.get(RULES_KEY), 'deny\texample.com\nallow\tok.example.org');
  assert.ok(kv.data.get(DATA_VERSION_KEY), 'version bumped');
  assert.equal(kv.stats.puts, 6, '3 saves x (1 blob + 1 version): migrate, put x2');

  assert.equal(await rs.delete('example.com'), true);
  assert.equal(await rs.delete('missing.test'), false);
  assert.deepEqual(await rs.list(), [{ domain: 'ok.example.org', kind: 'allow' }]);
});

test('RuleStore: match walks parents; allow wins over specific deny', async () => {
  const kv = new FakeKV();
  const rs = new RuleStore(kv);
  await rs.put('example.com', 'allow');
  await rs.put('ads.example.com', 'deny');

  assert.deepEqual(rs.match('a.b.example.com'), { kind: 'allow', at: 'example.com' });
  assert.deepEqual(rs.match('ads.example.com'), { kind: 'allow', at: 'example.com' },
    'allow at parent beats deny at exact name');
  assert.deepEqual(rs.match('other.test'), null);
  assert.equal(rs.lookup('www.example.com'), 'allow');
  // trailing dot tolerated
  assert.deepEqual(rs.match('example.com.'), { kind: 'allow', at: 'example.com' });
});

test('RuleStore: putBulk applies a whole batch in 1 read + 2 writes', async () => {
  const kv = new FakeKV();
  const rs = new RuleStore(kv);
  const entries = [
    { domain: 'a.com', kind: 'deny' },
    { domain: 'b.com', kind: 'deny' },
    { domain: '!!!bad!!!', kind: 'deny' },
    { domain: 'c.com', kind: 'wrong' },
  ];
  const added = await rs.putBulk(entries);
  assert.equal(added, 2, 'invalid entries skipped');
  assert.equal(kv.stats.gets, 2, 'version + blob');
  assert.equal(kv.stats.puts, 4, 'initial empty migration + one batch save (ea. blob+version)');
  assert.deepEqual(await rs.list(), [
    { domain: 'a.com', kind: 'deny' },
    { domain: 'b.com', kind: 'deny' },
  ]);

  // re-adding identical content is a no-op (0 changed -> 0 writes)
  const before = kv.stats.puts;
  const again = await rs.putBulk([{ domain: 'a.com', kind: 'deny' }]);
  assert.equal(again, 0);
  assert.equal(kv.stats.puts, before, 'no write when nothing changed');
});

test('RuleStore: version cache avoids blob re-reads on warm refreshes', async () => {
  const kv = new FakeKV();
  const rs = new RuleStore(kv);
  await rs.put('x.com', 'deny');

  // TTL still fresh -> zero I/O
  const before = kv.stats.gets;
  await rs.refresh();
  assert.equal(kv.stats.gets, before, 'fresh TTL -> no KV reads at all');

  // simulate TTL expiry: version unchanged -> only the version key is read
  rs.cachedAt = 0;
  await rs.refresh();
  assert.equal(kv.stats.gets, before + 1, 'expiry reads version only, not the blob');

  // another isolate writes -> version changes -> blob re-read
  rs.cachedAt = 0;
  kv.data.set(RULES_KEY, 'allow\ty.com');
  kv.data.set(DATA_VERSION_KEY, '999');
  await rs.refresh();
  assert.deepEqual(await rs.list(), [{ domain: 'y.com', kind: 'allow' }]);
});

test('RuleStore: KV read failure keeps stale rules, never an empty set', async () => {
  const kv = new FakeKV();
  const rs = new RuleStore(kv);
  await rs.put('keep.com', 'deny');

  kv.fail.get = true;
  await rs.refresh(true); // force — still fails, must keep data
  assert.deepEqual(await rs.list(), [{ domain: 'keep.com', kind: 'deny' }],
    'stale data survives a failed read');

  kv.fail.get = false;
  await rs.refresh(true);
  assert.deepEqual(await rs.list(), [{ domain: 'keep.com', kind: 'deny' }]);
});

test('RuleStore: legacy one-key layout migrates into the blob', async () => {
  const kv = new FakeKV({
    'rule:old1.com': 'deny',
    'rule:old2.com': 'allow',
    'rule:garbage': 'maybe',   // ignored
    'unrelated:key': 'x',      // ignored
  });
  const rs = new RuleStore(kv);
  await rs.refresh(true);
  assert.deepEqual(await rs.list(), [
    { domain: 'old1.com', kind: 'deny' },
    { domain: 'old2.com', kind: 'allow' },
  ]);
  assert.ok(kv.data.get(RULES_KEY), 'blob persisted after migration');
  assert.ok(kv.data.get('rule:old1.com'), 'legacy keys left in place');
});

test('RuleStore: failed legacy scan does not overwrite with empty blob', async () => {
  const kv = new FakeKV();
  kv.fail.list = true;
  const rs = new RuleStore(kv);
  await rs.refresh(true); // blob missing + list fails -> keep empty, write nothing
  assert.equal(kv.data.get(RULES_KEY), undefined, 'no blob written on failed scan');

  kv.fail.list = false;
  await rs.refresh(true);
  assert.equal(kv.data.get(RULES_KEY), '', 'clean install writes empty blob once');
});

// ---- normalizeDomain -----------------------------------------------------------

test('normalizeDomain: schemes, wildcards, ports, trailing dots, junk', () => {
  assert.equal(normalizeDomain('HTTPS://Sub.Example.COM/path?q=1'), 'sub.example.com');
  assert.equal(normalizeDomain('*.ads.example.com'), 'ads.example.com');
  assert.equal(normalizeDomain('.example.com'), 'example.com');
  assert.equal(normalizeDomain('example.com.'), 'example.com');
  assert.equal(normalizeDomain('example.com:8443'), 'example.com');
  assert.equal(normalizeDomain('a-b.co'), 'a-b.co');
  assert.equal(normalizeDomain('nodot'), '', 'must contain a dot');
  assert.equal(normalizeDomain('-bad.com'), '', 'label cannot start with dash');
  assert.equal(normalizeDomain('a..b.com'), '');
  assert.equal(normalizeDomain(''), '');
  assert.equal(normalizeDomain(42), '');
  assert.equal(normalizeDomain('x'.repeat(300) + '.com'), '');
});

// ---- TextSetStore --------------------------------------------------------------

test('TextSetStore: TLD normalization + add/remove', async () => {
  const kv = new FakeKV();
  const ts = new TextSetStore(kv, 'tlds:data');
  assert.equal(await ts.add('ZIP'), true, 'normalized to lowercase');
  assert.equal(await ts.add('.zip'), false, 'duplicate after normalization');
  assert.equal(await ts.add('com'), true);
  assert.deepEqual(ts.list(), ['com', 'zip']);
  assert.equal(await ts.remove('zip.'), true, 'trailing dot stripped');
  assert.equal(await ts.remove('nope'), false);
  assert.deepEqual(ts.list(), ['com']);
  assert.equal(kv.stats.puts, 6, '3 changed ops x (blob + version)');
});

test('normalizeTld / normalizeKeyword validation', () => {
  assert.equal(normalizeTld('.xyz'), 'xyz');
  assert.equal(normalizeTld('co.uk'), '', 'single label only');
  assert.equal(normalizeTld('a'), '', 'too short');
  assert.equal(normalizeTld('ok-9'), 'ok-9');
  assert.equal(normalizeKeyword('DoubleClick'), 'doubleclick');
  assert.equal(normalizeKeyword('bad_keyword!'), '');
  assert.equal(normalizeKeyword(''), '');
  assert.equal(normalizeKeyword('x'.repeat(65)), '');
});

test('TextSetStore: version cache + failure keeps stale set', async () => {
  const kv = new FakeKV({ 'k:data': 'one\ntwo' });
  const ts = new TextSetStore(kv, 'k:data');
  await ts.refresh(true);
  assert.deepEqual(ts.list(), ['one', 'two']);

  const gets = kv.stats.gets;
  ts.cachedAt = 0; // simulate TTL expiry
  await ts.refresh();
  assert.equal(kv.stats.gets, gets + 1, 'expiry reads version only');
  assert.deepEqual(ts.list(), ['one', 'two'], 'blob untouched on version match');

  kv.fail.get = true;
  await ts.refresh(true);
  assert.deepEqual(ts.list(), ['one', 'two'], 'stale set survives failed read');
});

// ---- SettingsStore -------------------------------------------------------------

test('SettingsStore: defaults, JSON load, partial update', async () => {
  const kv = new FakeKV();
  const ss = new SettingsStore(kv);
  await ss.refresh(true);
  assert.deepEqual(ss.get(), { ...DEFAULT_SETTINGS });

  await ss.update({ idnBlock: true });
  assert.equal(ss.get().idnBlock, true);
  const raw = JSON.parse(kv.data.get('settings:main') ?? '');
  assert.equal(raw.idnBlock, true);
  assert.equal(raw.rebindProtection, true, 'unrelated keys preserved');

  // fresh isolate reads it back
  const ss2 = new SettingsStore(kv);
  await ss2.refresh(true);
  assert.equal(ss2.get().idnBlock, true);
  assert.equal(ss2.get().logRetentionDays, 30, 'default fills missing key');
});

test('SettingsStore: cold read failure -> defaults; warm failure -> keep current', async () => {
  const kv = new FakeKV();
  kv.fail.get = true;
  const cold = new SettingsStore(kv);
  await cold.refresh(true);
  assert.deepEqual(cold.get(), { ...DEFAULT_SETTINGS }, 'cold start falls back to defaults');

  kv.fail.get = false;
  await cold.update({ idnBlock: true });
  kv.fail.get = true;
  await cold.refresh(true);
  assert.equal(cold.get().idnBlock, true, 'transient error must not reset toggles');
});

test('clampRetention: bounds and type checks', () => {
  assert.equal(clampRetention(0), 0);
  assert.equal(clampRetention(30), 30);
  assert.equal(clampRetention(-5), 0);
  assert.equal(clampRetention(99999), 3650);
  assert.equal(clampRetention(12.7), 12);
  assert.ok(Number.isNaN(clampRetention('30')));
  assert.ok(Number.isNaN(clampRetention(NaN)));
});

// ---- bulk import primitives ----------------------------------------------------

test('TextSetStore: addMany merges in one save; replaceAll swaps wholesale', async () => {
  const kv = new FakeKV();
  const ts = new TextSetStore(kv, 'tlds:data');
  await ts.add('zip');
  const putsBefore = kv.stats.puts;

  const r1 = await ts.addMany(['mov', 'ZIP', '.top', 'no!tld', ''], normalizeTld);
  assert.deepEqual(r1, { applied: 2, skipped: 2 }, 'mov+top applied; blank+invalid skipped; zip dedup');
  assert.ok(!ts.list().includes('no!tld'));
  assert.equal(kv.stats.puts, putsBefore + 2, 'exactly one save = blob + version');
  assert.deepEqual(ts.list().sort(), ['mov', 'top', 'zip']);

  const r2 = await ts.replaceAll(['io', 'bogus.tld!'], normalizeTld);
  assert.deepEqual(r2, { applied: 1, skipped: 1 });
  assert.deepEqual(ts.list(), ['io']);
  assert.equal(await ts.addMany([]).then((r) => r.applied), 0, 'empty input -> no write');
});

test('RuleStore: replaceAll swaps the whole map in one save', async () => {
  const kv = new FakeKV();
  const rs = new RuleStore(kv);
  await rs.put('old.com', 'deny');
  const putsBefore = kv.stats.puts;

  const n = await rs.replaceAll([
    { domain: 'a.com', kind: 'allow' },
    { domain: 'NO.dots..', kind: 'deny' },   // invalid -> dropped
    { kind: 'deny' },                         // no domain -> dropped
  ]);
  assert.equal(n, 1);
  assert.deepEqual(await rs.list(), [{ domain: 'a.com', kind: 'allow' }]);
  assert.equal(kv.stats.puts, putsBefore + 2, 'one save = blob + version');
});
