// test/blocklist.test.js — plaintext blocklist parsing + parent-label matching.
// The list format is one domain per line; comments/blank/malformed lines are skipped.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  Blocklist,
  DEFAULT_BLOCKLIST_URL,
  MAX_BLOCKLIST_URLS,
  MAX_SOURCE_ENTRIES,
  effectiveBlocklistUrls,
  normalizeBlocklistUrls,
  parseBlocklist,
} from '../blocklist.js';

test('load: plaintext lines parse; comments, blanks and malformed rows are skipped', () => {
  const bl = new Blocklist();
  bl.load([
    '# Hagezi pro-plus',
    'example.com',
    '',
    '   ',
    'sub.example.com',
    '.leading.dot.net',
    '*.wildcard.org',
    'trailing.dot.example.',
    'UPPER.EXAMPLE.ORG',
    '0.0.0.0 ads.hostsfile.test', // hosts rows parse to their domain(s)
    'plain.example.com # inline commentary, has whitespace -> skipped',
    'x'.repeat(300) + '.example.com', // >253 chars
  ].join('\n'));

  assert.equal(bl.size, 7);
  assert.ok(bl.domains.has('example.com'));
  assert.ok(bl.domains.has('sub.example.com'));
  assert.ok(bl.domains.has('leading.dot.net'), 'leading dot stripped');
  assert.ok(bl.domains.has('wildcard.org'), 'wildcard prefix stripped');
  assert.ok(bl.domains.has('trailing.dot.example'), 'trailing dot stripped');
  assert.ok(bl.domains.has('upper.example.org'), 'lowercased');
  assert.ok(!bl.domains.has('0.0.0.0'), 'hosts IP never becomes a domain');
  assert.ok(bl.domains.has('ads.hostsfile.test'), 'hosts row domain kept');
  assert.ok(bl.loadedAt > 0, 'fresh marker set for the 24h window');
});

test('load: adblock syntax ||domain^ normalizes to domains', () => {
  const bl = new Blocklist();
  bl.load([
    '! some comment',
    '[Adblock Plus 2.0]',
    '||example.com^',
    '||tracker.example.net^$third-party',
    '|single.example.org^',
    '||*.wild.example.io^',
    '||path.example.com^/images/banner.png',
    '@@||allowed.example.com^',
    '||zip.example.zip^',
  ].join('\n'));

  assert.equal(bl.size, 6);
  assert.ok(bl.domains.has('example.com'));
  assert.ok(bl.domains.has('tracker.example.net'), 'options after $ stripped');
  assert.ok(bl.domains.has('single.example.org'), 'single | prefix handled');
  assert.ok(bl.domains.has('wild.example.io'), '*. stripped');
  assert.ok(bl.domains.has('path.example.com'), 'cut at the ^ separator');
  assert.ok(bl.domains.has('zip.example.zip'));
  assert.ok(!bl.domains.has('allowed.example.com'), '@@ exception rules are not blocks');
  assert.equal(bl.match('a.b.example.com'), 'example.com', 'parent walking works for adblock entries');
  assert.equal(bl.match('sub.single.example.org'), 'single.example.org');
});

test('match: walks parent labels, reports the entry that matched', () => {
  const bl = new Blocklist();
  bl.load('ads.example.com\nevil.test\n');

  assert.equal(bl.match('ads.example.com'), 'ads.example.com');
  assert.equal(bl.match('x.ads.example.com'), 'ads.example.com', 'subdomain walks up');
  assert.equal(bl.match('a.b.example.com'), null, 'unlisted parent chain stays clean');
  assert.equal(bl.match('evil.test.'), 'evil.test', 'trailing dot tolerated');
  assert.equal(bl.isBlocked('tracker.evil.test'), true);
  assert.equal(bl.isBlocked('good.example.org'), false);
  assert.equal(typeof DEFAULT_BLOCKLIST_URL, 'string', 'default source exported');
});
test('exceptions: @@ lines parse into a separate set, both dialects', () => {
  const bl = new Blocklist();
  bl.load([
    '||example.com^',
    'ads.example.com',
    '@@clean.example.com',
    '@@||allowed.example.com^',
    '@@', // empty -> skipped
    '! @@comment-like line stays a comment',
  ].join('\n'));

  assert.equal(bl.size, 2, 'blocking rows unchanged');
  assert.equal(bl.exceptionSize, 2);
  assert.ok(!bl.domains.has('clean.example.com'), 'exception never blocks');
  assert.ok(!bl.domains.has('allowed.example.com'), 'adblock-dialect exception never blocks');
  assert.ok(bl.exceptions.has('clean.example.com'));
  assert.ok(bl.exceptions.has('allowed.example.com'));
  assert.equal(bl.exception('clean.example.com'), 'clean.example.com');
  assert.equal(bl.exception('x.y.allowed.example.com'), 'allowed.example.com', 'exceptions walk parents too');
  assert.equal(bl.exception('other.test'), null);
});

test('exceptions: a hit cancels the blocklist verdict only', () => {
  const bl = new Blocklist();
  bl.load(['example.com', '@@sub.example.com'].join('\n'));

  assert.equal(bl.isBlocked('sub.example.com'), false, 'exception wins over the block');
  assert.equal(bl.isBlocked('deep.sub.example.com'), false, 'exception applies to subdomains');
  assert.equal(bl.isBlocked('www.example.com'), true, 'sibling subdomain stays blocked');
  assert.equal(bl.isBlocked('example.com'), true, 'the blocked apex itself is not exempted');
});

test('exceptionRules: sorted allow rows tagged with the blocklist source', () => {
  const bl = new Blocklist();
  bl.load(['zblock.test', '@@b.example.com', '@@a.example.com'].join('\n'));

  assert.deepEqual(bl.exceptionRules(), [
    { domain: 'a.example.com', kind: 'allow', src: 'blocklist' },
    { domain: 'b.example.com', kind: 'allow', src: 'blocklist' },
  ]);
  bl.load('plain.test\n');
  assert.deepEqual(bl.exceptionRules(), [], 'no @@ lines -> no rows');
});

// ---- parseBlocklist -----------------------------------------------------------

test('parseBlocklist: returns blocking and exception sets without a Blocklist', () => {
  const { domains, exceptions } = parseBlocklist([
    '! comment',
    '||ads.example.com^',
    '0.0.0.0 tracker.example.net',
    '@@||cdn.example.com^',
    'not a domain line',
  ].join('\n'));

  assert.deepEqual([...domains].sort(), ['ads.example.com', 'tracker.example.net']);
  assert.deepEqual([...exceptions], ['cdn.example.com']);
  assert.deepEqual(parseBlocklist('').domains.size, 0, 'empty document is not an error');
});

// ---- multi-source subscriptions ------------------------------------------------

test('multi-source: the union answers, one list can be dropped without the other', () => {
  const bl = new Blocklist();
  const A = 'https://a.test/list';
  const B = 'https://b.test/list';

  bl.setSources([A, B]);
  bl.putSource(A, ['shared.test', 'only.a.test', '@@allow.a.test'].join('\n'));
  bl.putSource(B, ['shared.test', 'only.b.test', '@@allow.b.test'].join('\n'));

  assert.equal(bl.size, 3, 'union counts the shared domain once');
  assert.equal(bl.exceptionSize, 2, 'exceptions merge too');
  assert.equal(bl.match('x.only.a.test'), 'only.a.test');
  assert.equal(bl.match('only.b.test'), 'only.b.test');
  assert.equal(bl.isBlocked('allow.a.test'), false, 'a @@ row from any list exempts');

  bl.setSources([A]);
  assert.equal(bl.size, 2, 'dropping B frees its entries');
  assert.equal(bl.match('only.b.test'), null, 'B no longer blocks');
  assert.equal(bl.match('only.a.test'), 'only.a.test', 'A is untouched by the drop');
  assert.equal(bl.exceptionSize, 1, 'B exceptions dropped with it');
});

test('setSources: adding a URL keeps every loaded document in place', () => {
  const bl = new Blocklist();
  const A = 'https://a.test/list';
  bl.setSources([A]);
  bl.putSource(A, 'one.test\n');

  bl.setSources([A, 'https://c.test/list']);
  assert.equal(bl.size, 1, 'the new URL starts empty, A keeps its entries');
  assert.equal(bl.sourceLoaded('https://c.test/list'), false, 'not fetched yet');
  assert.equal(bl.sourceFresh('https://c.test/list', 1), false, 'loadedAt 0 is never fresh');
  assert.equal(bl.sourceFresh(A, 60_000), true, 'A still inside its window');
});

test('listSources: sorted per-subscription numbers, anonymous load excluded', () => {
  const bl = new Blocklist();
  bl.load('solo.test\n'); // anonymous '' source (back-compatible single document)

  assert.deepEqual(bl.listSources(), [], 'the "" document is not a subscription');

  bl.setSources(['https://z.test/list', 'https://a.test/list']);
  bl.putSource('https://z.test/list', 'z1.test\nz2.test\n@@z-ex.test\n');
  bl.putSource('https://a.test/list', 'a1.test\n');
  bl.sourceError('https://a.test/list', 'blocklist HTTP 500 for https://a.test/list');

  const sources = bl.listSources();
  assert.deepEqual(
    sources.map(({ url, entries, exceptions, error }) => ({ url, entries, exceptions, error })),
    [
      { url: 'https://a.test/list', entries: 1, exceptions: 0, error: 'blocklist HTTP 500 for https://a.test/list' },
      { url: 'https://z.test/list', entries: 2, exceptions: 1, error: null },
    ],
    'sorted by URL with per-source numbers',
  );
  assert.ok(sources.every((s) => s.loadedAt > 0), 'every loaded source carries its fetch time');
  assert.ok(bl.sourceLoaded('https://z.test/list'));
  bl.sourceError('https://z.test/list', 'network is down');
  assert.equal(bl.listSources()[1].error, 'network is down');
  bl.touchSource('https://z.test/list');
  assert.equal(bl.listSources()[1].error, null, 'a 304 clears the stale error');
  assert.equal(bl.listSources()[0].error, 'blocklist HTTP 500 for https://a.test/list',
    'touching one source never clears another');
});

// ---- normalizeBlocklistUrls ----------------------------------------------------

test('normalizeBlocklistUrls: https only, trimmed, de-duplicated, capped', () => {
  const a = 'https://a.test/list';
  const b = 'http://insecure.test/list'; // plain http is refused
  assert.deepEqual(normalizeBlocklistUrls([a, b]), [a], 'http rows are dropped, not fatal');
  assert.deepEqual(normalizeBlocklistUrls([`  ${a}  `, a]), [a], 'trimmed and deduped');
  assert.deepEqual(normalizeBlocklistUrls(['ftp://x.test/l', 42, null, 'not a url']), [], 'garbage rows dropped');
  assert.deepEqual(normalizeBlocklistUrls('https://a.test'), [], 'not an array');

  const many = Array.from({ length: 40 }, (_, i) => `https://l${i}.test/list`);
  assert.equal(normalizeBlocklistUrls(many).length, MAX_BLOCKLIST_URLS, `capped at ${MAX_BLOCKLIST_URLS}`);
});

test('normalizeBlocklistUrls: credentials in the URL are refused', () => {
  assert.deepEqual(normalizeBlocklistUrls(['https://user:pass@a.test/list']), [], 'no embedded credentials');
  assert.deepEqual(normalizeBlocklistUrls(['https://a.test/list']), ['https://a.test/list']);
});

// ---- effectiveBlocklistUrls (tri-state) -----------------------------------------

test('effectiveBlocklistUrls: null -> the deployment variable as its one entry', () => {
  const env = { BLOCKLIST_URL: 'https://env.test/list' };
  assert.deepEqual(effectiveBlocklistUrls({ blocklistUrls: null }, env), ['https://env.test/list']);
  assert.deepEqual(effectiveBlocklistUrls({ blocklistUrls: null }, {}), [DEFAULT_BLOCKLIST_URL],
    'no variable -> the built-in default');
  assert.deepEqual(
    effectiveBlocklistUrls({ blocklistUrls: null }, { BLOCKLIST_URL: '  https://spaced.test/list  ' }),
    ['https://spaced.test/list'],
    'the variable is trimmed',
  );
});

test('effectiveBlocklistUrls: [] means the remote blocklist is off on purpose', () => {
  assert.deepEqual(
    effectiveBlocklistUrls({ blocklistUrls: [] }, { BLOCKLIST_URL: 'https://env.test/list' }),
    [],
    'an empty stored list never falls back to the variable',
  );
});

test('effectiveBlocklistUrls: a saved list replaces the variable and is normalized', () => {
  assert.deepEqual(
    effectiveBlocklistUrls(
      { blocklistUrls: ['https://s.test/list', 'http://bad.test/list', 'https://s.test/list'] },
      { BLOCKLIST_URL: 'https://env.test/list' },
    ),
    ['https://s.test/list'],
    'the variable is ignored once the user saved a list; bad rows dropped',
  );
});

test('putSource: a document over the entry cap is refused and marked, previous copy stays', () => {
  const bl = new Blocklist();
  bl.putSource('https://l.test/one', 'keep.test\n');
  assert.equal(bl.size, 1);

  const rows = [];
  for (let i = 0; i <= MAX_SOURCE_ENTRIES; i++) rows.push(`e${i}.test`);
  bl.putSource('https://l.test/one', rows.join('\n'));

  assert.equal(bl.size, 1, 'the oversized parse never reaches the union');
  const src = bl.listSources().find((s) => s.url === 'https://l.test/one');
  assert.ok(src, 'the source is still listed');
  assert.match(String(src.error), /entry cap/, 'the refusal is visible on the source');
  assert.equal(bl.sourceFresh('https://l.test/one', 60_000), true, 'marked fresh: no re-parse on every request');
  assert.ok(bl.sourceLoaded('https://l.test/one'));
});
