// test/upstream.test.js — provider presets, the settings/env resolution order,
// patch validation, and the live connection test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  UPSTREAM_PRESETS, PROBE_NAME, findPreset, isHttpsUrl, probeUpstream, resolveUpstream,
  upstreamPatch, validateUpstreamSettings,
} from '../upstream.js';
import { buildQuery, buildResponse, v4rdata } from './helpers.js';
import { buildRefusedResponse } from '../dns.js';

const DEFAULT_SETTINGS = { upstreamPreset: '', upstreamUrl: '', upstreamRelay: '' };

test('presets: unique ids, https URLs, and the expected providers', () => {
  const ids = UPSTREAM_PRESETS.map((p) => p.id);
  assert.equal(new Set(ids).size, ids.length, 'ids are unique');

  for (const p of UPSTREAM_PRESETS) {
    if (p.id !== 'custom') assert.ok(isHttpsUrl(p.url), `${p.id} url is https`);
    assert.ok(p.label && p.group, `${p.id} has a label and a group`);
  }

  assert.equal(findPreset('cloudflare')?.url, 'https://cloudflare-dns.com/dns-query');
  assert.equal(findPreset('cloudflare-malware')?.url, 'https://security.cloudflare-dns.com/dns-query');
  assert.equal(findPreset('cloudflare-family')?.url, 'https://family.cloudflare-dns.com/dns-query');
  assert.equal(findPreset('cloudflare-odoh')?.kind, 'odoh');
  assert.equal(findPreset('quad9')?.url, 'https://dns.quad9.net/dns-query');
  assert.equal(findPreset('quad9-ecs')?.url, 'https://dns11.quad9.net/dns-query');
  assert.equal(findPreset('google')?.url, 'https://dns.google/dns-query');
  assert.equal(findPreset('adguard')?.url, 'https://dns.adguard-dns.com/dns-query');
  assert.equal(findPreset('adguard-family')?.url, 'https://family.adguard-dns.com/dns-query');
  assert.equal(findPreset('adguard-unfiltered')?.url, 'https://unfiltered.adguard-dns.com/dns-query');
  assert.equal(findPreset('nope'), undefined);
});

test('isHttpsUrl: https only, no credentials', () => {
  assert.equal(isHttpsUrl('https://dns.example/dns-query'), true);
  assert.equal(isHttpsUrl('http://dns.example/dns-query'), false);
  assert.equal(isHttpsUrl('https://user:pw@dns.example/dns-query'), false);
  assert.equal(isHttpsUrl('not a url'), false);
  assert.equal(isHttpsUrl(''), false);
  assert.equal(isHttpsUrl(null), false);
});

test('resolveUpstream: dashboard choice > UPSTREAM_URL > built-in default', () => {
  const env = { UPSTREAM_URL: 'https://deploy.example/dns-query' };

  const chosen = resolveUpstream({ ...DEFAULT_SETTINGS, upstreamPreset: 'google' }, env);
  assert.equal(chosen.id, 'google');
  assert.equal(chosen.url, 'https://dns.google/dns-query');
  assert.equal(chosen.source, 'settings');

  const deployed = resolveUpstream(DEFAULT_SETTINGS, env);
  assert.equal(deployed.source, 'deploy');
  assert.equal(deployed.url, 'https://deploy.example/dns-query');

  const fallback = resolveUpstream(DEFAULT_SETTINGS, {});
  assert.equal(fallback.source, 'default');
  assert.equal(fallback.id, 'quad9');
  assert.equal(fallback.url, 'https://dns.quad9.net/dns-query');

  // A custom provider with no URL yet must not become an empty upstream.
  const halfCustom = resolveUpstream({ ...DEFAULT_SETTINGS, upstreamPreset: 'custom' }, env);
  assert.equal(halfCustom.source, 'deploy', 'falls back until a URL is entered');

  const custom = resolveUpstream(
    { ...DEFAULT_SETTINGS, upstreamPreset: 'custom', upstreamUrl: 'https://doh.internal/dns-query' },
    env,
  );
  assert.equal(custom.id, 'custom');
  assert.equal(custom.url, 'https://doh.internal/dns-query');
  assert.equal(custom.source, 'settings');

  const odoh = resolveUpstream(
    { ...DEFAULT_SETTINGS, upstreamPreset: 'cloudflare-odoh', upstreamRelay: 'https://relay.example/proxy{?targethost,targetpath}' },
    {},
  );
  assert.equal(odoh.kind, 'odoh');
  assert.equal(odoh.url, 'https://odoh.cloudflare-dns.com/dns-query');
  assert.match(odoh.relay, /targethost/);
});

test('validateUpstreamSettings: custom needs a URL, ODoH needs a usable relay', () => {
  assert.equal(validateUpstreamSettings(DEFAULT_SETTINGS), null, 'no explicit choice is fine');
  assert.equal(validateUpstreamSettings({ ...DEFAULT_SETTINGS, upstreamPreset: 'quad9' }), null);
  assert.match(
    String(validateUpstreamSettings({ ...DEFAULT_SETTINGS, upstreamPreset: 'custom' })),
    /https:\/\/ DoH URL/,
  );
  assert.equal(
    validateUpstreamSettings({ ...DEFAULT_SETTINGS, upstreamPreset: 'custom', upstreamUrl: 'https://doh.example/dns-query' }),
    null,
  );
  assert.match(
    String(validateUpstreamSettings({ ...DEFAULT_SETTINGS, upstreamPreset: 'cloudflare-odoh' })),
    /relay URL/,
  );
  assert.match(
    String(validateUpstreamSettings({ ...DEFAULT_SETTINGS, upstreamPreset: 'cloudflare-odoh', upstreamRelay: 'https://relay.example/proxy' })),
    /targethost/,
  );
  assert.equal(
    validateUpstreamSettings({
      ...DEFAULT_SETTINGS,
      upstreamPreset: 'cloudflare-odoh',
      upstreamRelay: 'https://relay.example/proxy{?targethost,targetpath}',
    }),
    null,
  );
});

test('upstreamPatch: whitelists and validates, trimming what it keeps', () => {
  assert.deepEqual(upstreamPatch({}), { patch: null, error: null });
  assert.deepEqual(upstreamPatch({ idnBlock: true }), { patch: null, error: null });

  assert.deepEqual(upstreamPatch({ upstreamPreset: 'google' }), { patch: { upstreamPreset: 'google' }, error: null });
  assert.deepEqual(upstreamPatch({ upstreamPreset: '' }), { patch: { upstreamPreset: '' }, error: null }, 'clearing is allowed');
  assert.match(String(upstreamPatch({ upstreamPreset: 'cloudflare ' }).error), /unknown upstream provider/);
  assert.match(String(upstreamPatch({ upstreamPreset: 7 }).error), /must be a string/);
  assert.match(String(upstreamPatch({ upstreamUrl: 'http://doh.example' }).error), /https:\/\//);
  assert.deepEqual(
    upstreamPatch({ upstreamUrl: '  https://doh.example/dns-query  ' }),
    { patch: { upstreamUrl: 'https://doh.example/dns-query' }, error: null },
  );
  assert.deepEqual(
    upstreamPatch({ upstreamRelay: '  https://relay.example/proxy{?targethost,targetpath} ' }).patch,
    { upstreamRelay: 'https://relay.example/proxy{?targethost,targetpath}' },
  );
});

test('probeUpstream: a real query goes to the chosen endpoint and reports latency', async () => {
  let seenUrl = '';
  let seenType = '';
  const fetchImpl = /** @type {typeof fetch} */ (async (input, init) => {
    seenUrl = String(input);
    seenType = new Headers(init?.headers).get('content-type') || '';
    return new Response(buildResponse(buildQuery(PROBE_NAME), [{ type: 1, rdata: v4rdata('93.184.216.34'), ttl: 60 }]));
  });

  const result = await probeUpstream(
    { url: 'https://dns.google/dns-query', kind: 'doh' },
    { fetchImpl, now: (() => { let t = 1000; return () => (t += 25); })() },
  );

  assert.equal(seenUrl, 'https://dns.google/dns-query');
  assert.equal(seenType, 'application/dns-message');
  assert.equal(result.ok, true);
  assert.equal(result.ms, 25);
  assert.equal(result.rcode, 0);
  assert.equal(result.answers, 1);
  assert.equal(result.sample, '93.184.216.34');
});

test('probeUpstream: HTTP errors, DNS errors, garbage and bad input fail cleanly', async () => {
  const httpFail = await probeUpstream(
    { url: 'https://dns.example/dns-query', kind: 'doh' },
    { fetchImpl: /** @type {typeof fetch} */ (async () => new Response('down', { status: 503 })) },
  );
  assert.equal(httpFail.ok, false);
  assert.match(String(httpFail.error), /HTTP 503/);

  const servfail = await probeUpstream(
    { url: 'https://dns.example/dns-query', kind: 'doh' },
    { fetchImpl: /** @type {typeof fetch} */ (async () => new Response(buildRefusedResponse(buildQuery(PROBE_NAME)))) },
  );
  assert.equal(servfail.ok, false);
  assert.match(String(servfail.error), /REFUSED/);

  const garbage = await probeUpstream(
    { url: 'https://dns.example/dns-query', kind: 'doh' },
    { fetchImpl: /** @type {typeof fetch} */ (async () => new Response('nope')) },
  );
  assert.equal(garbage.ok, false);
  assert.match(String(garbage.error), /unreadable/);

  const network = await probeUpstream(
    { url: 'https://dns.example/dns-query', kind: 'doh' },
    { fetchImpl: /** @type {typeof fetch} */ (async () => { throw new Error('connect timeout'); }) },
  );
  assert.equal(network.ok, false);
  assert.match(String(network.error), /connect timeout/);

  const badUrl = await probeUpstream({ url: 'http://dns.example', kind: 'doh' });
  assert.equal(badUrl.ok, false);
  assert.match(String(badUrl.error), /https/);
});

test('probeUpstream: ODoH without a usable relay never reaches the network', async () => {
  let calls = 0;
  const fetchImpl = /** @type {typeof fetch} */ (async () => {
    calls++;
    return new Response('unexpected');
  });

  const result = await probeUpstream(
    { url: 'https://odoh.cloudflare-dns.com/dns-query', kind: 'odoh', relay: 'https://relay.example/proxy' },
    { fetchImpl },
  );
  assert.equal(result.ok, false);
  assert.match(String(result.error), /targethost/);
  assert.equal(calls, 0);
});
