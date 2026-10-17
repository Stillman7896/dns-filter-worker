// test/blocklist.test.js — plaintext blocklist parsing + parent-label matching.
// The list format is one domain per line; comments/blank/malformed lines are skipped.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Blocklist, DEFAULT_BLOCKLIST_URL } from '../blocklist.js';

test('load: plaintext lines parse; comments, blanks and hosts rows are skipped', () => {
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
    '0.0.0.0 ads.hostsfile.test', // hosts-file rows are not domains
    'plain.example.com # inline commentary, has whitespace -> skipped',
    'x'.repeat(300) + '.example.com', // >253 chars
  ].join('\n'));

  assert.equal(bl.size, 6);
  assert.ok(bl.domains.has('example.com'));
  assert.ok(bl.domains.has('sub.example.com'));
  assert.ok(bl.domains.has('leading.dot.net'), 'leading dot stripped');
  assert.ok(bl.domains.has('wildcard.org'), 'wildcard prefix stripped');
  assert.ok(bl.domains.has('trailing.dot.example'), 'trailing dot stripped');
  assert.ok(bl.domains.has('upper.example.org'), 'lowercased');
  assert.ok(!bl.domains.has('0.0.0.0'), 'hosts IP dropped');
  assert.ok(!bl.domains.has('ads.hostsfile.test'), 'hosts domain dropped');
  assert.ok(bl.loadedAt > 0, 'fresh marker set for the 24h window');
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