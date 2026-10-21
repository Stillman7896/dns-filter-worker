// test/blocklist.test.js — plaintext blocklist parsing + parent-label matching.
// The list format is one domain per line; comments/blank/malformed lines are skipped.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Blocklist, DEFAULT_BLOCKLIST_URL } from '../blocklist.js';

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
