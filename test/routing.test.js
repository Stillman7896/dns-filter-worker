// test/routing.test.js — response routes: value normalization, the KV blob,
// subdomain matching, synthesized answers, and their place in the filter chain.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  RouteStore, normalizeRoute, normalizeRouteValue, parseRouteLine, formatRouteLine,
  routeRecords, clampTtl, DEFAULT_ROUTE_TTL,
} from '../routing.js';
import {
  buildAnswerResponse, buildQueryMessage, questionEnd, parseIpv4, parseIpv6,
  summariseAnswers, RR, encodeName,
} from '../dns.js';
import { runQueryFilters } from '../filters.js';
import { FakeKV } from './helpers.js';

const q = (/** @type {string} */ name, /** @type {number} */ qtype = 1) => buildQueryMessage(name, qtype);
const ancount = (/** @type {Uint8Array} */ buf) => (buf[6] << 8) | buf[7];

// ---- values ----

test('route values: IP literals pick the record type, hostnames become CNAMEs', () => {
  assert.deepEqual(normalizeRouteValue('192.168.1.10'), { type: 'a', value: '192.168.1.10' });
  assert.deepEqual(normalizeRouteValue('0.0.0.0'), { type: 'a', value: '0.0.0.0' }, 'null route');
  assert.deepEqual(normalizeRouteValue('10.0.0.1'), { type: 'a', value: '10.0.0.1' }, 'private is allowed');
  assert.deepEqual(normalizeRouteValue('::1'), { type: 'aaaa', value: '::1' });
  assert.deepEqual(normalizeRouteValue('fd00::12'), { type: 'aaaa', value: 'fd00::12' });
  assert.deepEqual(normalizeRouteValue('::ffff:192.168.0.2'), { type: 'aaaa', value: '::ffff:192.168.0.2' });
  assert.deepEqual(normalizeRouteValue('NAS.Home.LAN.'), { type: 'cname', value: 'nas.home.lan' });
  assert.deepEqual(normalizeRouteValue('https://media.example.com/path'), { type: 'cname', value: 'media.example.com' });

  assert.equal(normalizeRouteValue('999.1.1.1'), null);
  assert.equal(normalizeRouteValue('1.2.3'), null);
  assert.equal(normalizeRouteValue('not a name'), null);
  assert.equal(normalizeRouteValue(''), null);
  assert.equal(normalizeRouteValue(null), null);
});

test('route ttl: defaults to 300s and clamps to one day', () => {
  assert.equal(clampTtl(NaN), DEFAULT_ROUTE_TTL);
  assert.equal(clampTtl(-5), 0);
  assert.equal(clampTtl(12.9), 12);
  assert.equal(clampTtl(999_999), 86_400);
});

test('normalizeRoute: rejects a type that contradicts the value', () => {
  assert.deepEqual(
    normalizeRoute({ domain: 'printer.home.lan', value: '192.168.1.9', ttl: 60 }),
    { domain: 'printer.home.lan', type: 'a', value: '192.168.1.9', ttl: 60 },
  );
  assert.equal(normalizeRoute({ domain: 'printer.home.lan', value: '192.168.1.9', type: 'cname' }), null);
  assert.equal(normalizeRoute({ domain: 'nodots', value: '1.2.3.4' }), null);
  assert.equal(normalizeRoute({ domain: 'a.example.com' }), null);

  const line = formatRouteLine({ domain: 'media.example.com', type: 'cname', value: 'nas.home.lan', ttl: 120 });
  assert.equal(line, 'media.example.com\tcname\tnas.home.lan\t120');
  assert.deepEqual(parseRouteLine(line), { domain: 'media.example.com', type: 'cname', value: 'nas.home.lan', ttl: 120 });
  assert.equal(parseRouteLine('broken line'), null);
  assert.equal(parseRouteLine('a.example.com\ta\tnonsense\t60'), null);
});

// ---- store ----

test('RouteStore: put/list/delete persist one KV blob and match subdomains', async () => {
  const kv = new FakeKV();
  const store = new RouteStore(kv);

  await store.put({ domain: 'example.com', value: '203.0.113.9', ttl: 60 });
  await store.put({ domain: 'media.example.com', value: 'nas.home.lan' });
  assert.deepEqual(store.list().map((r) => r.domain), ['example.com', 'media.example.com']);

  const blob = kv.data.get('routes:data');
  assert.ok(blob, 'routes:data written');
  assert.match(String(blob), /^example\.com\ta\t203\.0\.113\.9\t60$/m);
  assert.ok(kv.data.get('data:version'), 'shared version bumped');

  // most specific route wins, parents cover subdomains
  assert.equal(store.match('media.example.com')?.value, 'nas.home.lan');
  assert.equal(store.match('img.media.example.com')?.value, 'nas.home.lan');
  assert.equal(store.match('www.example.com')?.value, '203.0.113.9');
  assert.equal(store.match('other.test'), null);

  assert.equal(await store.delete('media.example.com'), true);
  assert.equal(await store.delete('media.example.com'), false);
  assert.equal(store.match('media.example.com')?.value, '203.0.113.9', 'parent route applies again');
});

test('RouteStore: a failed read keeps the routes already in memory', async () => {
  const kv = new FakeKV();
  const store = new RouteStore(kv);
  await store.put({ domain: 'keep.example.com', value: '192.0.2.1' });

  kv.fail.get = true;
  await store.refresh(true);
  assert.equal(store.match('keep.example.com')?.value, '192.0.2.1', 'not wiped by a KV error');
  kv.fail.get = false;
});

test('RouteStore: import merge/replace reports what it applied', async () => {
  const kv = new FakeKV();
  const store = new RouteStore(kv);

  const merged = await store.addMany([
    { domain: 'a.example.com', value: '192.0.2.2' },
    { domain: 'bad.domain', value: 'nope' },
  ]);
  assert.deepEqual(merged, { applied: 1, skipped: 1 });

  const replaced = await store.replaceAll([
    { domain: 'b.example.com', value: '2001:db8::1' },
    { nonsense: true },
  ]);
  assert.deepEqual(replaced, { applied: 1, skipped: 1 });
  assert.deepEqual(store.list().map((r) => r.domain), ['b.example.com']);
});

// ---- answers ----

test('routeRecords: only the covered type is answered; others are NODATA', () => {
  const a = routeRecords({ type: 'a', value: '192.168.1.10', ttl: 60 }, 'printer.home.lan', RR.A);
  assert.equal(a.length, 1);
  assert.equal(a[0].type, RR.A);
  assert.deepEqual([...a[0].rdata], [192, 168, 1, 10]);
  assert.equal(a[0].ttl, 60);
  assert.deepEqual(routeRecords({ type: 'a', value: '192.168.1.10', ttl: 60 }, 'printer.home.lan', RR.AAAA), []);

  const aaaa = routeRecords({ type: 'aaaa', value: 'fd00::12', ttl: 30 }, 'v6.home.lan', RR.AAAA);
  assert.equal(aaaa[0].type, RR.AAAA);
  assert.equal(aaaa[0].rdata.length, 16);
  assert.deepEqual(routeRecords({ type: 'aaaa', value: 'fd00::12', ttl: 30 }, 'v6.home.lan', RR.A), []);

  const cname = routeRecords({ type: 'cname', value: 'media.example.com', ttl: 300 }, 'img.example.com', RR.A);
  assert.equal(cname[0].type, RR.CNAME);
  assert.deepEqual([...cname[0].rdata], [...encodeName('media.example.com')]);
  assert.equal(
    routeRecords({ type: 'cname', value: 'media.example.com', ttl: 300 }, 'img.example.com', RR.AAAA).length,
    1,
    'a CNAME covers every type',
  );
});

test('buildAnswerResponse: echoes the question, sets AA/RA, appends records', () => {
  const query = q('printer.home.lan', RR.A);
  const response = buildAnswerResponse(query, routeRecords({ type: 'a', value: '192.168.1.10', ttl: 60 }, 'printer.home.lan', RR.A));

  assert.equal(response[2] & 0x80, 0x80, 'QR');
  assert.equal(response[2] & 0x04, 0x04, 'AA');
  assert.equal(response[2] & 0x01, 0x01, 'RD copied');
  assert.equal(response[3] & 0x0f, 0, 'NOERROR');
  assert.equal(ancount(response), 1);
  assert.equal((response[8] << 8) | response[9], 0, 'NSCOUNT');
  assert.equal((response[10] << 8) | response[11], 0, 'ARCOUNT');
  assert.equal(questionEnd(response), questionEnd(query), 'question section intact');

  const summary = summariseAnswers(response);
  assert.deepEqual(summary, { rcode: 0, count: 1, sample: '192.168.1.10' });

  const nodata = buildAnswerResponse(query, []);
  assert.equal(nodata[3] & 0x0f, 0);
  assert.equal(ancount(nodata), 0);
  assert.equal(nodata.length, questionEnd(query), 'nothing appended');

  const broken = buildAnswerResponse(new Uint8Array(4), []);
  assert.equal(broken[3] & 0x0f, 5, 'unparseable query -> REFUSED');
});

test('wire helpers: questionEnd, IP parsers, summariseAnswers guards', () => {
  assert.equal(questionEnd(q('a.b.c')), q('a.b.c').length);
  assert.equal(questionEnd(new Uint8Array(12)), -1, 'no question');
  assert.equal(questionEnd(null), -1);

  assert.deepEqual([.../** @type {Uint8Array} */ (parseIpv4(' 1.2.3.4 '))], [1, 2, 3, 4]);
  assert.equal(parseIpv4('1.2.3.256'), null);
  assert.deepEqual([.../** @type {Uint8Array} */ (parseIpv6('2001:db8::1'))].slice(0, 4), [0x20, 0x01, 0x0d, 0xb8]);
  assert.equal(parseIpv6('1.2.3.4'), null);
  assert.equal(parseIpv6('2001::db8::1'), null);
  assert.equal(parseIpv6('2001:db8:1:2:3:4:5:6:7'), null);

  assert.equal(summariseAnswers(new Uint8Array(3)), null);
  assert.deepEqual(summariseAnswers(buildAnswerResponse(q('x.example'), [])), { rcode: 0, count: 0, sample: null });
  const truncated = buildAnswerResponse(q('x.example'), []).subarray(0, 14);
  assert.equal(summariseAnswers(truncated)?.count, 0, 'truncated answer section is tolerated');
});

// ---- precedence ----

test('filters: a route outranks allow/deny rules and the blocklist', () => {
  const routeStore = /** @type {any} */ ({
    match: (/** @type {string} */ name) =>
      name === 'media.example.com' || name.endsWith('.media.example.com')
        ? { type: 'a', value: '192.168.1.10', ttl: 60, at: 'media.example.com' }
        : null,
  });
  const ruleStore = /** @type {any} */ ({
    match: (/** @type {string} */ name) =>
      name.endsWith('media.example.com') ? { kind: 'deny', at: 'media.example.com' } : null,
  });
  const blocklist = /** @type {any} */ ({ match: () => null });
  const keywordStore = /** @type {any} */ ({ get: () => new Set() });
  const tldStore = /** @type {any} */ ({ get: () => new Set() });

  const verdict = runQueryFilters(
    { routeStore, ruleStore, blocklist, keywordStore, tldStore },
    { rebindProtection: true, idnBlock: false, tldBlock: false, keywordBlock: false },
    'img.media.example.com',
  );
  assert.equal(verdict.status, 'route');
  assert.equal(verdict.filter, 'route');
  assert.deepEqual(verdict.route, { type: 'a', value: '192.168.1.10', ttl: 60, at: 'media.example.com' });

  // Without the route store the deny rule decides, exactly as before.
  const denied = runQueryFilters(
    { ruleStore, blocklist, keywordStore, tldStore },
    { rebindProtection: true, idnBlock: false, tldBlock: false, keywordBlock: false },
    'img.media.example.com',
  );
  assert.equal(denied.status, 'deny');
});
