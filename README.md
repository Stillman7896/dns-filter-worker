# DNS Filter — DoH endpoint with blocklist + custom rules + dashboard

DNS over HTTPS (RFC 8484) endpoint for Cloudflare Workers. Filters against the
Hagezi `pro-plus` blocklist and a user-managed allow/deny rule set stored in
Workers KV, answers chosen names locally, and forwards everything else to a
resolver picked from the dashboard (Cloudflare, Quad9, Google, AdGuard — plain
DoH or Oblivious DoH — or your own endpoint).

## Precedence

```
Response route — a fixed answer for the name + subdomains
  > Custom denylist
  > Custom allowlist
  > Remote blocklist (Hagezi pro-plus)
  > Blocked TLD (last-label match)                       [if tldBlock]
  > Blocked keyword (substring match)                    [if keywordBlock]
  > DNS rebinding — internal/special-use names           [if rebindProtection]
  > IDN homograph block — xn-- / non-ASCII labels        [if idnBlock]
  > Upstream resolver (Settings, or UPSTREAM_URL)
  > DNS rebinding — private IP in the ANSWER section      [if rebindProtection]
```

A route answers first because it is a direct instruction about that name: the
worker never asks an upstream for it, and it outranks even an explicit deny
rule. Allow wins over deny everywhere else, so you can carve holes in the
upstream Hagezi list — including letting an allowlisted name resolve to a
private IP past the rebinding check.

### DNS rebinding protection (`rebindProtection`, default ON)
- **Name level**: blocks `localhost`, `*.local`, `*.lan`, `*.home`, `*.internal`,
  `*.intranet`, `*.corp`, `*.private`, `*.home.arpa`, `*.test`, `*.invalid`,
  `*.example` (RFC 6761/6762 special-use).
- **Answer level**: after upstream resolves, walks the ANSWER section and blocks
  any A/AAAA record that is private or link-local — `10/8`, `172.16/12`,
  `192.168/16`, `127/8`, `169.254/16` (cloud metadata), `100.64/10` (CGNAT),
  `0/8`, `::`, `::1`, `fc00::/7`, `fe80::/10`, plus v4-mapped `::ffff:x.x.x.x`.

### IDN homograph block (`idnBlock`, default OFF)
Blunt "block everything" mode: any label starting with `xn--`, or any label
containing non-ASCII bytes (raw UTF-8 from non-compliant clients) is blocked.
A one-bit toggle — there is no partial/smart mode.

### Blocked TLDs (`tldBlock`, default OFF)
Compares only the **last label** against a `Set` — a single hash lookup.
Blocked example: `.zip`, `.mov` (look like file extensions), `.xyz`, `.tk`.

### Blocked keywords (`keywordBlock`, default OFF)
Substring match of the query name against each entry. Entries must be
specific (`doubleclick`, `adservice`) — a short entry like `ad` will break a
large share of the web.

#### How fast is keyword matching?

`name.includes(kw)` over K entries on an L-character string is `O(K·L)` in the
worst case. With K = 50 entries and L = 60 chars that's ~3,000 char comparisons,
**well under 1 µs** — `String.prototype.includes` uses a fast search path in V8,
and for ASCII-only needles it degrades to near-`memchr` speed.

Context for what that costs:

| Operation on the query path | Typical cost |
|---|---|
| Keyword match (50 entries) | **< 1 µs** |
| TLD `Set.has` | **~50 ns** |
| Blocklist walk (4 labels) | ~200 ns |
| KV read (when TTL expires) | 1–10 ms |
| **Network round trip to upstream** | **5–50 ms** |

Matching is ~10,000× cheaper than one network round trip, so it is
effectively free. The real scaling concern is **load time**, not match time —
which is exactly why lists are stored as one KV blob (see *Storage design*
below) rather than one key per entry.

Guardrails already in place:
- Both checks are skipped entirely (no iteration, no `Set.has`) unless their
  toggle is on.
- Both are skipped when the list is empty (`list.size` check first).
- Keywords are iterated in insertion order — put longer/more specific entries
  first so common domains match later entries less often.

## Storage design (and why not one key per rule)

**KV has *unlimited* keys per namespace**, so key count is never the limit.
The limits that actually matter are [documented by Cloudflare](https://developers.cloudflare.com/kv/platform/limits):

| Limit | Value | Effect of one-key-per-rule |
|---|---|---|
| Keys / namespace | **Unlimited** | fine |
| **Operations / invocation** | **1,000** | `list()` + N×`get()` for 5k rules = **5,000 ops → hard failure** |
| Free: writes to *different* keys | **1,000 / day** | 5k rule edits/day exhausts it |
| Free: reads | 100,000 / day | N reads per cold start burns this quickly |
| Value size | 25 MiB | one blob holds ~1M domains |
| Writes to the *same* key | 1 / sec | irrelevant at one write per change |

So each list lives in **one KV value**:

| Key | Contents |
|---|---|
| `rules:data` | newline `kind<TAB>domain` |
| `keywords:data` | newline keywords |
| `tlds:data` | newline TLDs |
| `routes:data` | newline `domain<TAB>type<TAB>value<TAB>ttl` |
| `settings:main` | JSON of the toggles + the chosen provider |
| `data:version` | timestamp bumped on **any** list write |

A shared `data:version` means one tiny read per cache TTL tells *every* store
whether its blob changed — so a warm DNS query performs **zero** KV reads, and
a cold one performs at most 4.

Writes are read-modify-write on the single blob (1 read + 1 write), and bulk
import uses `putBulk()` — one read + one write for the whole batch instead of
one pair per rule.

> **Known trade-off:** two writes racing on the same blob are last-write-wins,
> so a rule added during another isolate's save could be dropped. This only
> matters for concurrent editors; a single admin won't notice.

### Legacy one-key-per-rule layout
Earlier versions stored `rule:<domain>` keys. Those are migrated into
`rules:data` automatically on first load (read-only — they're left in place so
cleanup doesn't consume the free plan's write quota). To reclaim the keys
after migrating:

```bash
wrangler kv:key list --prefix=rule: --namespace-id=<ID>   # inspect
wrangler kv:bulk delete --namespace-id=<ID> --prefix=rule: # then remove
```

## Files

| File                | Purpose                                             |
|---------------------|-----------------------------------------------------|
| `worker.js`         | Worker entrypoint, routing, full filter pipeline    |
| `dns.js`            | DNS wire parsing + response builders (Workers/Node) |
| `blocklist.js`      | Hagezi remote list loader + subdomain matcher       |
| `rules.js`          | KV-backed allow/deny store (single blob) + subdomain matching |
| `lists.js`          | Generic newline KV blob stores (keywords, TLDs) + normalizers |
| `settings.js`       | KV-backed persistent filter settings (toggles, provider) |
| `routing.js`        | KV-backed response routes + record synthesis        |
| `upstream.js`       | Provider presets, resolution order, connection probe |
| `odoh.js`           | Oblivious DoH client: HPKE (RFC 9180) + ODoH (RFC 9230) |
| `dashboard.js`      | JSON API for rules/routes/logs/settings/session     |
| `assets/index.html` | Dashboard UI (static Worker asset)                  |
| `schema.sql`        | D1 schema for query audit logs                      |
| `wrangler.toml`     | Worker config, assets, KV, D1, runtime vars         |

## Endpoints

| Path              | Description                                                            |
|-------------------|------------------------------------------------------------------------|
| `/dns-query`      | DoH endpoint (GET `?dns=` or POST `application/dns-message`)            |
| `/`               | 302 → `/dashboard` when the client sends `Accept: text/html`           |
| `/dashboard`      | Dashboard UI (static asset, SPA fallback)                               |
| `/api/rules`      | List / add (POST `{domain,kind}`) / delete                              |
| `/api/rules/bulk` | Bulk import `{kind, domains}`                                           |
| `/api/test`       | Run full pipeline for a domain (mirrors live filtering)                |
| `/api/settings`   | Get (GET: settings + resolved provider + preset list) / save (POST `{rebindProtection, idnBlock, tldBlock, keywordBlock, logPassed, logRetentionDays, upstreamPreset, upstreamUrl, upstreamRelay}`) |
| `/api/routes`     | List / add (POST `{domain,value,ttl?}`) / delete (`?domain=`) response routes |
| `/api/upstream/test` | Send one real query to a candidate provider: `{ok, ms, rcode, answers, sample}` or `{ok:false, error}` |
| `/api/filters/tlds` | List (GET) / add (POST `{value}`) / remove (DELETE `?value=`) blocked TLDs |
| `/api/filters/keywords` | Same, for blocked keywords                              |
| `/api/logs`       | Search + paginate logs (GET); delete filtered/all (DELETE)             |
| `/api/logs/:id`   | Delete a single log row                                                |
| `/api/session`    | Login (sets session cookie)                                             |
| `/healthz`        | Stats, effective settings, resolved URLs                                |

## Upstream resolver

The resolver is a **dashboard setting**, stored in KV and switched without a
redeploy. `env.UPSTREAM_URL` still works, but only as a fallback for a
deployment that has never picked a provider:

```
Dashboard provider (KV)  >  UPSTREAM_URL (wrangler [vars])  >  built-in default
```

| Preset | Endpoint | What it adds |
|---|---|---|
| Cloudflare | `cloudflare-dns.com` | nothing — fast and neutral |
| Cloudflare — malware protection | `security.cloudflare-dns.com` | blocks malware/phishing |
| Cloudflare — family | `family.cloudflare-dns.com` | malware + adult content |
| Cloudflare — oblivious (ODoH) | `odoh.cloudflare-dns.com` | encrypted through a relay you name |
| Quad9 | `dns.quad9.net` | blocks malware/phishing |
| Quad9 — ECS | `dns11.quad9.net` | no blocking, forwards client subnet |
| Google Public DNS | `dns.google` | nothing |
| AdGuard DNS / family / unfiltered | `*.adguard-dns.com` | ads, or ads + adult content, or nothing |
| Custom DoH URL | yours | anything RFC 8484 |

**Test connection** sends a real `example.com` A query to the chosen endpoint
(or to the URL you are typing) and reports latency, rcode and the first answer —
so a typo or an unreachable resolver shows up before a client ever asks.

### Oblivious DoH

ODoH needs a relay: the query is HPKE-sealed for the resolver's key, the relay
forwards ciphertext, and neither hop learns both the name and your address. The
worker fetches the target key from
`https://<target>/.well-known/odohconfigs` (cached 6 h) and accepts any relay
that speaks the RFC 9230 URI template:

```
https://relay.example/proxy{?targethost,targetpath}
```

Relay URIs are operator-specific — there is no default, and the panel refuses
to save the preset without one. A saved relay that stops working makes queries
fail with SERVFAIL; the connection test is the quickest way to notice.

The relay is only used for forwarding: no plaintext query is ever sent to it,
and the relay URL is never shared with the target.

## Domain response routing

Settings → Domain response routing answers a domain, and every subdomain of it,
with a fixed record instead of asking upstream:

| Answer you type | Record served | Good for |
|---|---|---|
| `192.168.1.20` | A | devices on the LAN |
| `fd00::20` | AAAA | IPv6 hosts |
| `nas.home.lan` | CNAME | aliasing one name onto another |

- Routes are checked **before every other filter**, including allow/deny rules.
- Private and special-use names are allowed on purpose (`nas.home.lan` is the
  point); the rebinding guard does not second-guess a route.
- A route covers only its own record type. An `A` route answers `A` queries and
  returns NODATA (NOERROR, no records) for everything else, so an overridden
  name never leaks to the upstream on another type.
- TTL is per route (default 300 s, max 86400) and is what clients are told.

## Runtime configuration

The blocklist URL is still a deploy-time variable:

```toml
[vars]
BLOCKLIST_URL = "https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/pro-plus/domains"
```

```bash
wrangler deploy --var BLOCKLIST_URL:https://example.com/mylist.txt
```

Its edge cache key derives from `BLOCKLIST_URL`, so switching the URL never
serves a stale cached copy. The default lives in `blocklist.js`
(`DEFAULT_BLOCKLIST_URL`).

## Deploy

```bash
npm i -g wrangler

# 1. KV namespace (custom allow/deny rules)
wrangler kv:namespace create RULES
wrangler kv:namespace create RULES --preview
# paste ids into wrangler.toml

# 2. D1 database (query logs)
wrangler d1 create dns-logs
wrangler d1 execute dns-logs --file=./schema.sql
# paste database_id into wrangler.toml

# 3. Dashboard password
wrangler secret put DASHBOARD_PASSWORD

# 4. Deploy
wrangler deploy
```

The dashboard UI is a static asset: `wrangler` bundles `assets/` per the
`[assets]` block (`binding = "ASSETS"`), and the Worker serves it for any
non-API, non-`/dns-query` path. `run_worker_first = true` lets the Worker
route `/api/*` and `/dns-query` before falling through to the assets, and
`not_found_handling = "single-page-application"` makes `/dashboard` serve
`index.html`.

Point a DoH client (e.g. Firefox, AdGuard Home, `curl`) at:
`https://<your-worker>.workers.dev/dns-query`

The dashboard's Overview shows that URL with a copy button and a setup guide
per client type — the endpoint is always this worker's own origin, so there is
nothing to configure twice.

## Dashboard auth

There is a **single** login mechanism: the in-page password form. The browser
native HTTP password dialog is intentionally not used (no `WWW-Authenticate`
header is ever sent). The form posts to `/api/session`, which sets a session
cookie.

If `DASHBOARD_PASSWORD` is not set, the dashboard is **disabled** with a clear
"not configured" message — it does not prompt for a password. DoH filtering
still works normally in that case.

## Custom rules

Rules are stored in KV under `rule:<domain>` = `allow` | `deny`. Adding a rule
for `example.com` matches `*.example.com` too (subdomain walk). `allow` at any
parent wins over a `deny` at a more specific name.

## Filter settings

| Setting            | Default | KV key                       |
|--------------------|---------|------------------------------|
| `rebindProtection` | `true`  | `settings:main` (JSON blob)  |
| `idnBlock`         | `false` | `settings:main` (JSON blob)  |
| `tldBlock`         | `false` | `settings:main` (JSON blob)  |
| `keywordBlock`     | `false` | `settings:main` (JSON blob)  |
| `logPassed`        | `true`  | `settings:main` (JSON blob)  |
| `logRetentionDays` | `30`    | `settings:main` (JSON blob)  |
| `upstreamPreset`   | `''` (deploy var, else Quad9) | `settings:main` |
| `upstreamUrl`      | `''`    | `settings:main` (custom provider) |
| `upstreamRelay`    | `''`    | `settings:main` (ODoH relay) |

Managed from the **Settings** tab. Persisted to KV (same namespace as rules),
so they survive deploys and are shared across every colo.

**Propagation:** each isolate caches settings for 30 s and reads are
zero-I/O on the DNS hot path — after the first load, a query never touches
KV for settings. A save updates the writing isolate immediately; other
isolates pick it up within ~30 s.

## Query logs

Every resolved query is written to D1 (`dns_logs`) with:

- `domain` — requested QNAME (lowercased)
- `status` — `route` | `allow` | `deny` | `blocklist` | `tld` | `keyword` | `rebind` | `idn` | `none`
- `filter` — which layer decided: `route` | `allowlist` | `denylist` | `blocklist` | `tld` | `keyword` | `rebind` | `idn` | `upstream`
- `ts` — unix epoch ms
- `qtype` — DNS RR type number (`1`=A, `28`=AAAA, `16`=TXT, `65`=HTTPS, …), shown in the
  dashboard as the common mnemonic (`A`, `AAAA`, `HTTPS`, …), `other` for uncommon codes,
  and `—` for rows written before this column existed.

`qtype` is added to pre-existing tables automatically on the first insert
(`ALTER TABLE ... ADD COLUMN`, duplicate-column errors ignored), so no manual
migration is needed.

The Logs tab supports search, status filter, paging (Prev/Next + rows-per-page),
per-row delete, delete-filtered, and clear-all. `filter` is redundant with
`status` in the UI, so the table shows `status` only.
