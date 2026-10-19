// upstream.js — the resolver this worker forwards to.
//
// Providers are a fixed set of presets (the URL nobody should have to
// remember) plus a custom DoH URL, all chosen from the dashboard and stored in
// KV. `env.UPSTREAM_URL` still works: it is the fallback whenever no provider
// has been picked in the dashboard, so an existing deployment keeps resolving
// the way it did before.

import { buildQueryMessage, summariseAnswers } from './dns.js';
import { expandRelayTemplate, odohForward } from './odoh.js';

export const DNS_MEDIA_TYPE = 'application/dns-message';
export const OBLIVIOUS_MEDIA_TYPE = 'application/oblivious-dns-message';

/** Name used by the connection test: public, filter-neutral, always resolvable. */
export const PROBE_NAME = 'example.com';

export const RCODE_TEXT = /** @type {Record<number, string>} */ (Object.freeze({
  0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
  4: 'NOTIMP', 5: 'REFUSED',
}));

/**
 * @typedef {object} UpstreamPreset
 * @property {string} id
 * @property {string} label
 * @property {string} group
 * @property {string} url
 * @property {'doh'|'odoh'} kind
 * @property {string} note
 * @property {boolean} [needsUrl] custom URL entered in the dashboard
 */

/** @type {ReadonlyArray<UpstreamPreset>} */
export const UPSTREAM_PRESETS = Object.freeze([
  {
    id: 'cloudflare', label: 'Cloudflare', group: 'Cloudflare',
    url: 'https://cloudflare-dns.com/dns-query', kind: 'doh',
    note: '1.1.1.1 — fast, no filtering of its own.',
  },
  {
    id: 'cloudflare-malware', label: 'Cloudflare — malware protection', group: 'Cloudflare',
    url: 'https://security.cloudflare-dns.com/dns-query', kind: 'doh',
    note: '1.1.1.2 — blocks known malware and phishing domains.',
  },
  {
    id: 'cloudflare-family', label: 'Cloudflare — family', group: 'Cloudflare',
    url: 'https://family.cloudflare-dns.com/dns-query', kind: 'doh',
    note: '1.1.1.3 — malware protection plus adult content.',
  },
  {
    id: 'cloudflare-odoh', label: 'Cloudflare — oblivious (ODoH)', group: 'Cloudflare',
    url: 'https://odoh.cloudflare-dns.com/dns-query', kind: 'odoh',
    note: 'Encrypted to the resolver through a relay, so no single party sees both the name and your address. Needs a relay URL.',
  },
  {
    id: 'quad9', label: 'Quad9', group: 'Quad9',
    url: 'https://dns.quad9.net/dns-query', kind: 'doh',
    note: '9.9.9.9 — blocks malware and phishing domains.',
  },
  {
    id: 'quad9-ecs', label: 'Quad9 — ECS', group: 'Quad9',
    url: 'https://dns11.quad9.net/dns-query', kind: 'doh',
    note: '9.9.9.11 — no filtering, and passes on the client subnet for closer answers.',
  },
  {
    id: 'google', label: 'Google Public DNS', group: 'Google',
    url: 'https://dns.google/dns-query', kind: 'doh',
    note: '8.8.8.8 — no filtering of its own.',
  },
  {
    id: 'adguard', label: 'AdGuard DNS', group: 'AdGuard',
    url: 'https://dns.adguard-dns.com/dns-query', kind: 'doh',
    note: 'Blocks ads and trackers.',
  },
  {
    id: 'adguard-family', label: 'AdGuard DNS — family', group: 'AdGuard',
    url: 'https://family.adguard-dns.com/dns-query', kind: 'doh',
    note: 'Adds adult content blocking and forces safe search.',
  },
  {
    id: 'adguard-unfiltered', label: 'AdGuard DNS — unfiltered', group: 'AdGuard',
    url: 'https://unfiltered.adguard-dns.com/dns-query', kind: 'doh',
    note: 'No filtering of its own.',
  },
  {
    id: 'custom', label: 'Custom DoH URL', group: 'Custom',
    url: '', kind: 'doh', needsUrl: true,
    note: 'Any RFC 8484 endpoint you run or trust.',
  },
]);

/** Preset used when neither the dashboard nor the deployment names one. */
export const DEFAULT_PRESET_ID = 'quad9';

/** @param {unknown} id @returns {UpstreamPreset|undefined} */
export function findPreset(id) {
  return UPSTREAM_PRESETS.find((p) => p.id === id);
}

/** @param {unknown} value @returns {boolean} */
export function isHttpsUrl(value) {
  if (typeof value !== 'string' || !value.trim()) return false;
  try {
    const url = new URL(value.trim());
    return url.protocol === 'https:' && !url.username && !url.password;
  } catch {
    return false;
  }
}

/**
 * The provider actually used for a query.
 *
 * Precedence: a provider picked in the dashboard > `env.UPSTREAM_URL` >
 * the built-in default. The dashboard therefore never needs a redeploy to
 * change resolvers, and a deployment that only ever set the variable is
 * unaffected.
 * @param {{upstreamPreset?: string, upstreamUrl?: string, upstreamRelay?: string}|null} settings
 * @param {{UPSTREAM_URL?: string}|null} [env]
 * @returns {{id: string, label: string, group: string, kind: 'doh'|'odoh', url: string, relay: string, source: 'settings'|'deploy'|'default', note?: string}}
 */
export function resolveUpstream(settings, env) {
  const s = settings || {};
  const preset = s.upstreamPreset ? findPreset(s.upstreamPreset) : undefined;

  if (preset && preset.id === 'custom') {
    const custom = typeof s.upstreamUrl === 'string' ? s.upstreamUrl : '';
    if (isHttpsUrl(custom)) {
      return { id: 'custom', label: 'Custom DoH URL', group: 'Custom', kind: 'doh', url: custom.trim(), relay: '', source: 'settings' };
    }
  } else if (preset) {
    const kind = preset.kind || 'doh';
    const relay = kind === 'odoh' && typeof s.upstreamRelay === 'string' ? s.upstreamRelay.trim() : '';
    return {
      id: preset.id, label: preset.label, group: preset.group, kind,
      url: preset.url, relay, source: 'settings', note: preset.note,
    };
  }

  const envUrl = env && typeof env.UPSTREAM_URL === 'string' ? env.UPSTREAM_URL : '';
  if (isHttpsUrl(envUrl)) {
    return {
      id: 'deploy', label: 'UPSTREAM_URL variable', group: 'Deployment',
      kind: 'doh', url: envUrl.trim(), relay: '', source: 'deploy',
      note: 'Set in the Worker configuration, not in this dashboard.',
    };
  }

  const fallback = /** @type {UpstreamPreset} */ (findPreset(DEFAULT_PRESET_ID));
  return {
    id: fallback.id, label: fallback.label, group: fallback.group, kind: 'doh',
    url: fallback.url, relay: '', source: 'default', note: fallback.note,
  };
}

/**
 * Is this stored combination usable? Checked before a save so the dashboard
 * can never leave the resolver without a working upstream.
 * @param {Pick<FilterSettings, 'upstreamPreset'|'upstreamUrl'|'upstreamRelay'>} settings
 * @returns {string|null} error message, or null
 */
export function validateUpstreamSettings(settings) {
  const preset = settings.upstreamPreset ? findPreset(settings.upstreamPreset) : undefined;
  if (!preset) return null; // no explicit choice: the deploy variable / default applies
  if (preset.id === 'custom') {
    if (!isHttpsUrl(settings.upstreamUrl)) return 'a custom provider needs an https:// DoH URL';
    return null;
  }
  if (preset.kind === 'odoh') {
    const relay = typeof settings.upstreamRelay === 'string' ? settings.upstreamRelay : '';
    if (!relay) return 'ODoH needs a relay URL, for example https://relay.example/proxy{?targethost,targetpath}';
    if (!expandRelayTemplate(relay, 'target.example', '/dns-query')) {
      return 'the relay must be an https:// template containing {?targethost,targetpath}';
    }
  }
  return null;
}

/**
 * Whitelist the upstream fields out of a settings patch.
 * @param {Record<string, unknown>} source
 * @returns {{patch: {upstreamPreset?: string, upstreamUrl?: string, upstreamRelay?: string}|null, error: string|null}}
 */
export function upstreamPatch(source) {
  /** @type {{upstreamPreset?: string, upstreamUrl?: string, upstreamRelay?: string}} */
  const patch = {};

  if ('upstreamPreset' in source) {
    const id = typeof source.upstreamPreset === 'string' ? source.upstreamPreset : null;
    if (id === null) return { patch: null, error: 'upstreamPreset must be a string' };
    if (id !== '' && !findPreset(id)) return { patch: null, error: 'unknown upstream provider' };
    patch.upstreamPreset = id;
  }
  if ('upstreamUrl' in source) {
    const url = typeof source.upstreamUrl === 'string' ? source.upstreamUrl.trim() : null;
    if (url === null) return { patch: null, error: 'upstreamUrl must be a string' };
    if (url && !isHttpsUrl(url)) return { patch: null, error: 'a custom provider needs an https:// DoH URL' };
    patch.upstreamUrl = url;
  }
  if ('upstreamRelay' in source) {
    const relay = typeof source.upstreamRelay === 'string' ? source.upstreamRelay.trim() : null;
    if (relay === null) return { patch: null, error: 'upstreamRelay must be a string' };
    patch.upstreamRelay = relay;
  }

  if (Object.keys(patch).length === 0) return { patch: null, error: null };
  return { patch, error: null };
}

/**
 * Send one real query to `candidate` and report what came back.
 * @param {{url: string, kind?: 'doh'|'odoh', relay?: string}} candidate
 * @param {{fetchImpl?: typeof fetch, now?: () => number}} [opts]
 * @returns {Promise<{ok: boolean, ms: number, url: string, relay?: string, kind: string, rcode?: number, answers?: number, sample?: string|null, error?: string}>}
 */
export async function probeUpstream(candidate, opts = {}) {
  const fetchImpl = opts.fetchImpl || fetch;
  const now = opts.now || Date.now;
  const kind = candidate.kind === 'odoh' ? 'odoh' : 'doh';
  const started = now();

  /** @param {string} error @param {number} [ms] */
  const fail = (error, ms) => ({
    ok: false,
    error,
    ms: ms === undefined ? now() - started : ms,
    url: candidate.url,
    kind,
  });

  if (!isHttpsUrl(candidate.url)) return fail('not an https:// endpoint', 0);

  const query = buildQueryMessage(PROBE_NAME, 1);

  try {
    let answer;
    if (kind === 'odoh') {
      const relay = typeof candidate.relay === 'string' ? candidate.relay : '';
      if (!expandRelayTemplate(relay, 'target.example', '/dns-query')) {
        return fail('the relay must be an https:// template containing {?targethost,targetpath}', 0);
      }
      answer = await odohForward(candidate.url, relay, query, { fetchImpl });
    } else {
      const res = await fetchImpl(candidate.url, {
        method: 'POST',
        headers: { 'Content-Type': DNS_MEDIA_TYPE, Accept: DNS_MEDIA_TYPE },
        body: query,
      });
      if (!res.ok) return fail(`upstream HTTP ${res.status}`);
      answer = new Uint8Array(await res.arrayBuffer());
    }

    const summary = summariseAnswers(answer);
    if (!summary) return fail('the upstream sent an unreadable DNS message');
    const ms = now() - started;
    if (summary.rcode !== 0) {
      return { ok: false, error: `upstream answered ${RCODE_TEXT[summary.rcode] || `rcode ${summary.rcode}`}`, ms, url: candidate.url, relay: candidate.relay || undefined, kind, rcode: summary.rcode };
    }
    return {
      ok: true,
      ms,
      url: candidate.url,
      relay: candidate.relay || undefined,
      kind,
      rcode: summary.rcode,
      answers: summary.count,
      sample: summary.sample,
    };
  } catch (e) {
    return fail(e instanceof Error ? e.message : String(e));
  }
}
