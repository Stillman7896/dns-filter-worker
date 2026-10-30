# Configuration reference

Everything an operator can change: deploy-time variables, the settings the
dashboard writes to KV, the API surface, the blocklist file formats and the
upstream resolver.

- [Runtime variables](#runtime-variables)
- [Settings](#settings)
- [Endpoints](#endpoints)
- [Allow and deny rules](#allow-and-deny-rules)
- [Blocklist files and subscriptions](#blocklist-files-and-subscriptions)
- [Blocked TLDs, keywords and regex](#blocked-tlds-keywords-and-regex)
- [Domain response routing](#domain-response-routing)
- [Upstream resolver](#upstream-resolver)
- [Dashboard authentication](#dashboard-authentication)
- [Query logs](#query-logs)
- [Escape hatch: `/healthz/reset`](#escape-hatch-healthzreset)

## Runtime variables

`wrangler.toml` `[vars]`, or `wrangler secret put` for the password. Read on
every request; changing them needs a re-deploy.

| Variable | Required | Purpose |
|---|---|---|
| `BLOCKLIST_URL` | no | The **default subscription** — the document a fresh deployment starts with, until a list is saved from the dashboard. |
| `UPSTREAM_URL` | no | Fallback resolver, used only while no provider has been picked in the dashboard. |
| `UPSTREAM_FALLBACK_URL` | no | Fallback DoH endpoint for the failover path. |
| `DASHBOARD_PASSWORD` | no | Enables the dashboard. **Set it as a secret, not in `[vars]`.** |

```toml
[vars]
BLOCKLIST_URL = "https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/pro-plus/domains"
UPSTREAM_URL = "https://dns.quad9.net/dns-query"
UPSTREAM_FALLBACK_URL = "https://dns.google/dns-query"
```

```sh
wrangler deploy --var BLOCKLIST_URL:https://example.com/mylist.txt
wrangler secret put DASHBOARD_PASSWORD
```

`BLOCKLIST_URL` is a `null`-able tri-state. `null` (never saved) uses this
variable, a saved array replaces it, `[]` turns the remote blocklist off. When
the list is saved the variable's URL is kept as an ordinary first row, so
nothing the operator configured disappears silently. Its edge cache key derives
from the URL itself, so switching either never serves a stale cached copy. The
built-in default (`DEFAULT_BLOCKLIST_URL`) is used when the variable is unset.

## Settings

Managed from the **Settings** tab, except `blocklistUrls` (the subscription
list, managed entirely in **Filter lists**) — `regexBlock` is also switchable
from the header of its **Filter lists** section, next to the patterns it gates.
All of it persists to KV (the same namespace as rules), so it survives deploys
and is shared across every colo.

| Setting | Default | Stored in |
|---|---|---|
| `rebindProtection` | `true` | `settings:main` |
| `idnBlock` | `false` | `settings:main` |
| `tldBlock` | `false` | `settings:main` |
| `keywordBlock` | `false` | `settings:main` |
| `regexBlock` | `false` | `settings:main` |
| `blocklistUrls` | `null` (deploy var) | `settings:main` |
| `logPassed` | `true` | `settings:main` |
| `logRetentionDays` | `30` | `settings:main` |
| `upstreamPreset` | `''` (deploy var, else Quad9) | `settings:main` |
| `upstreamUrl` | `''` | `settings:main` |
| `upstreamRelay` | `''` | `settings:main` |
| `upstreamFailover` | `true` | `settings:main` |
| `upstreamFallbackUrl` | `''` | `settings:main` |
| `blockedResponse` | `'nxdomain'` | `settings:main` |

**Propagation:** each isolate caches settings for 30 s and reads are zero-I/O on
the DNS hot path — after the first load, a query never touches KV for settings.
A save updates the writing isolate immediately; other isolates pick it up within
~30 s.

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

### Blocked query response (`blockedResponse`, default `nxdomain`)

What the resolver sends back for a name that a filter stopped — the answer is
synthesized locally, no upstream is contacted:

| Value | Wire answer | Notes |
|---|---|---|
| `nxdomain` | RCODE 3, no records | The default; what most ad-blockers do. |
| `refused` | RCODE 5, no records | Cheap and unambiguous; some clients retry elsewhere. |
| `null_ip` | RCODE 0 with `0.0.0.0` (A) or `::` (AAAA), TTL 300 | The connection fails at once. The record family follows the query, so an AAAA query never gets an A record. |
| `nodata` | RCODE 0, no records | The name "exists" without a record of that type. |

It applies to every block layer — blocklist, deny rules, blocked TLDs,
keywords, regex, IDN and rebinding — plus the non-`IN` class reject. It does
**not** apply to routes: a response route always answers with its own record,
and an upstream failure still answers SERVFAIL. The chosen value is part of the
answer-cache key, so switching it takes effect on the next query rather than
after `BLOCKED_MAX_AGE` (300 s) expires.

## Endpoints

| Path | Description |
|---|---|
| `/dns-query` | DoH endpoint (RFC 8484; GET `?dns=` or POST `application/dns-message`); optional client tag via `/dns-query/<tag>` or `?tag=` |
| `/` | 302 → `/dashboard` when the client sends `Accept: text/html` |
| `/dashboard` | Dashboard UI (static asset, SPA fallback) |
| `/api/rules` | List / add (POST `{domain,kind}`) / delete |
| `/api/rules/bulk` | Bulk import `{kind, domains}` |
| `/api/test` | Run full pipeline for a domain (mirrors live filtering) |
| `/api/settings` | Get (GET: settings + resolved provider + preset list + `blocklist` payload) / save (POST `{rebindProtection, idnBlock, tldBlock, keywordBlock, regexBlock, blocklistUrls, logPassed, logRetentionDays, upstreamPreset, upstreamUrl, upstreamRelay, upstreamFailover, upstreamFallbackUrl, blockedResponse}`) |
| `/api/blocklists` | List (GET: subscriptions + `total`/`entryLimit`/`maxUrls`) / add (POST `{url}`) / remove (DELETE `?url=`) |
| `/api/blocklists/refresh` | Revalidate every subscription against its origin (POST) |
| `/api/routes` | List / add (POST `{domain,value,ttl?}`) / delete (`?domain=`) |
| `/api/upstream/test` | Send one real query to a candidate provider: `{ok, ms, rcode, answers, sample}` or `{ok:false, error}` |
| `/api/filters/tlds` | List / add (POST `{value}`) / remove (DELETE `?value=`) |
| `/api/filters/keywords` | Same, for blocked keywords |
| `/api/filters/regex` | Same, for regex rules |
| `/api/logs` | Search + paginate logs (GET, `?client=` / `?untagged=1`); delete filtered/all (DELETE) |
| `/api/logs/:id` | Delete a single log row |
| `/api/session` | Login (POST sets the session cookie, DELETE signs out) |
| `/healthz` | Stats, effective settings, resolved URLs (503 + `problems[]` when degraded) |
| `/healthz/reset` | Factory-reset hatch (POST, password-gated) |

## Allow and deny rules

Rules are stored in KV under `rule:<domain>` = `allow` | `deny`. Adding a rule
for `example.com` matches `*.example.com` too (subdomain walk). `allow` at any
parent wins over a `deny` at a more specific name.

The dashboard **Rules** page splits them into Block and Allow views, and every
row carries a source badge: *custom* rows live in KV and can be deleted there;
*blocklist* rows are `@@` exceptions from the remote list, shown read-only (the
API answers 400 on a delete attempt).

## Blocklist files and subscriptions

The remote list is parsed into a domain set; any of the common formats can be
mixed in one file:

| Line | Meaning |
|---|---|
| `example.com` | plain domain |
| `\|\|example.com^` | AdBlock (`$options` and paths stripped) |
| `\|\|*.example.com^` | AdBlock wildcard (`*.` prefix dropped) |
| `0.0.0.0 example.com` | hosts row (any count of domains) |
| `@@example.com` | **exception** — allow |
| `@@\|\|example.com^` | exception, AdBlock dialect |

Matching walks parent labels: an entry `example.com` also stops
`ads.example.com`, and the entry that matched is what gets logged.

`@@` exceptions cancel the blocklist verdict only — the name continues down the
precedence chain (blocked TLD, keywords, regex, rebinding, upstream). They are
surfaced in the dashboard under **Rules → Allow** as read-only rows tagged
*blocklist*; deleting them there is refused by the API because the source of
truth is the list file itself.

### Subscriptions

A deployment can subscribe to several documents at once (up to
`MAX_BLOCKLIST_URLS` = 10, https only). They are parsed independently and merged
into one set, so an entry blocks as soon as any subscription carries it — and
dropping one subscription frees only that document's entries. Each `@@`
exception applies to the whole union.

Which documents run is a tri-state, stored in `settings:main` as `blocklistUrls`:

| Value | Meaning |
|---|---|
| `null` | not saved yet — the `BLOCKLIST_URL` deploy variable is the one entry |
| an array | exactly those URLs; the deploy variable is ignored |
| `[]` | no remote blocklist at all (a deliberate state, not a fallback) |

The default runs as an ordinary row of the subscription list — editable and
deletable like any other — and saving the list persists the default alongside
it. The dashboard's **Filter lists** tab manages all of this: add/remove URLs,
one **Reload** button that revalidates every subscription against its origin
(conditional fetch, an unchanged document costs a single 304), and a warning
label when the merged `total` passes `BLOCKLIST_ENTRY_LIMIT` (1,000,000)
entries — beyond that the free plan's isolate memory can be exhausted. The same
budget is enforced on the worker, not just signalled: a single document over
`MAX_SOURCE_ENTRIES` (400,000) or `MAX_SOURCE_BYTES` (24 MB) is refused before
its parse (the previous copy keeps answering, the reason is shown on the
subscription row and `/healthz`), and a new subscription is refused while the
merged total is already at the entry limit. Those two lines are the CPU story —
the free plan's 10 ms budget is spent parsing documents, so the caps stop one
runaway list from taking the resolver (and the dashboard API) down with it. Each
row shows its own entry count, exception count, last fetch time and fetch error,
so a dead host is visible without guessing which one it was.

Loading is per-subscription and stale-while-revalidate: a fresh copy answers
with no network work, a cold colo fetches once, and a failed refresh keeps the
last good copy. Only when **no** document could be loaded at all does the
resolver return `503`. A change to the URL set rotates the config epoch, so an
answer cached under the previous set is never replayed.

## Blocked TLDs, keywords and regex

### Blocked TLDs (`tldBlock`, default OFF)

Compares only the **last label** against a `Set` — a single hash lookup.
Blocked example: `.zip`, `.mov` (look like file extensions), `.xyz`, `.tk`.

### Blocked keywords (`keywordBlock`, default OFF)

Substring match of the query name against each entry. Entries are validated,
never rewritten — lowercase letters, digits, dashes and dots only, 4–64
characters, kept exactly as entered (`.zip`, `-ads` are distinct needles). The
4-character minimum keeps over-eager entries out; still pick specific ones
(`doubleclick`, `adservice`) — short entries break a large share of the web.

Guardrails:

- Both keyword and TLD checks are skipped entirely (no iteration, no `Set.has`)
  unless their toggle is on.
- Both are skipped when the list is empty (`list.size` check first).
- Keywords are iterated in insertion order — put longer/more specific entries
  first so common domains match later entries less often.

### Regex rules (`regexBlock`, default OFF)

Each entry is a JavaScript regular expression tested against the **full
lowercase query name** (anchored automatically — `ads` matches only a name that
*is* ads-like; use `(^|\.)ads\.` for subdomain positions). Entries are validated
on add: 4–128 characters, no whitespace, and must compile — a broken pattern is
rejected at the API, never stored.

Patterns are compiled **once per list change** and cached until the backing KV
set is replaced (a refresh that changes nothing does not recompile), so the hot
path is one `RegExp.test` per pattern — no allocation per query. Iteration stops
at the first hit and reports the pattern that matched.

Keep patterns anchored-by-nature (`^` ... `$` are added for you) and prefer them
over keywords when the rule is positional or structured
(`^track\.[a-z0-9]+\.net$`); prefer keywords for plain substring bans, which are
~10× cheaper per entry. Catastrophic-backtracking patterns are the operator's
responsibility — the pattern list is yours, keep it small.

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

**Test connection** sends a real `example.com` A query to the chosen endpoint (or
to the URL you are typing) and reports latency, rcode and the first answer — so
a typo or an unreachable resolver shows up before a client ever asks.

### Oblivious DoH

ODoH needs a relay: the query is HPKE-sealed for the resolver's key, the relay
forwards ciphertext, and neither hop learns both the name and your address. The
worker fetches the target key from `https://<target>/.well-known/odohconfigs`
(cached 6 h) and accepts any relay that speaks the RFC 9230 URI template:

```
https://relay.example/proxy{?targethost,targetpath}
```

Relay URIs are operator-specific — there is no default, and the panel refuses to
save the preset without one. A saved relay that stops working makes queries fail
with SERVFAIL; the connection test is the quickest way to notice. The relay is
only used for forwarding: no plaintext query is ever sent to it, and the relay
URL is never shared with the target.

### Upstream failover

With `upstreamFailover` on (the default), a failed primary is retried **once**
on a fallback DoH server before the client sees an error. Retried: network
errors, HTTP 5xx, and SERVFAIL/REFUSED answers. Not retried: NXDOMAIN and NODATA
— those are real answers, and retrying them would double every negative lookup.

The fallback is picked in this order:

```
upstreamFallbackUrl (dashboard) > UPSTREAM_FALLBACK_URL (deploy var)
  > a built-in preset from a different operator than the primary
```

The fallback is always plain DoH — an ODoH relay is a second moving part exactly
when the first hop just failed. If the fallback also fails, the primary's answer
(or error) stands. Turn the whole thing off with `upstreamFailover: false` and a
dead primary returns SERVFAIL directly.

### Answer caching and negative caching

Resolved answers are cached at the edge and in an isolate LRU, keyed by the
query name, type, EDNS state, and the current upstream configuration — so
switching provider or fallback never serves answers from the old resolver.
Positive answers honour their record TTLs. **NXDOMAIN and NODATA** (NOERROR with
zero answer records) are cached for **60 s**: long enough to collapse a burst of
retries against the upstream, short enough that a record added at the
authoritative server is visible again almost immediately.

## Dashboard authentication

There is a **single** login mechanism: the in-page password form. The browser
native HTTP password dialog is intentionally not used (no `WWW-Authenticate`
header is ever sent). The form posts to `/api/session`, which sets a session
cookie that lives for 24 hours and is `HttpOnly`.

If `DASHBOARD_PASSWORD` is not set, the dashboard is **disabled** with a clear
"not configured" message — it does not prompt for a password. DoH filtering
still works normally in that case.

### Client tags

Give a device its own tagged endpoint — `https://<worker>/dns-query/laptop`,
`.../dns-query/tv`, or `?tag=laptop` — and every query from it is labelled in the
logs. The dashboard's Overview builds a ready-to-paste tagged URL. Invalid tags
are rejected with `400` before anything is logged, so a typo fails loudly.

## Query logs

Every resolved query is written to D1 (`dns_logs`) with:

- `domain` — requested QNAME (lowercased)
- `client` — device tag, lowercased; `null` for untagged queries
- `status` — `route` | `allow` | `deny` | `blocklist` | `tld` | `keyword` | `regex` | `rebind` | `idn` | `none`
- `filter` — which layer decided: `route` | `allowlist` | `denylist` | `blocklist` | `tld` | `keyword` | `regex` | `rebind` | `idn` | `upstream`
- `ts` — unix epoch ms
- `qtype` — DNS RR type number (`1`=A, `28`=AAAA, `16`=TXT, `65`=HTTPS, ...), shown in the dashboard as the common mnemonic (`A`, `AAAA`, `HTTPS`, ...), `other` for uncommon codes, and `—` for rows written before this column existed

The table and its indexes are created lazily by the Worker on the first logged
query, and `qtype`/`client` are added to pre-existing tables automatically
(`ALTER TABLE ... ADD COLUMN`, duplicate-column errors ignored), so no manual
migration is needed. `schema.sql` is the same schema for operators who prefer to
apply it up front.

Set `logPassed: false` to store only blocked queries, `logRetentionDays: 0` to
keep rows forever (default 30).

The **Logs** tab supports search, status filter, client-tag filter, paging
(Prev/Next + rows-per-page), per-row delete, delete-filtered, and clear-all.
`filter` is redundant with `status` in the UI, so the table shows `status` only.

## Escape hatch: `/healthz/reset`

A deployment can configure itself into a corner (too many blocklists, one
monster list) until every request dies on the CPU or memory budget — including
the dashboard API that would let you undo it. `POST /healthz/reset` exists for
exactly that: it runs before any store or blocklist work, needs only the
dashboard password, and wipes the KV configuration (settings, custom rules,
routes, filter lists, legacy rule rows). Deployment variables and the D1 query
log are untouched. The dashboard password doubles as the token, so no second
secret is involved:

```sh
curl -X POST https://<worker>.workers.dev/healthz/reset \
  -H 'Authorization: Bearer <DASHBOARD_PASSWORD>'
# or:  --data '{"password":"<DASHBOARD_PASSWORD>"}'
```

It is disabled (403) when no `DASHBOARD_PASSWORD` is set, and the same action is
a **Reset worker** button in the dashboard's Filter lists tab. When the worker
stops answering altogether, the dashboard's failure screen prints this exact
curl command — that is the only screen such a worker can still show. The hatch
is deliberately off `/api/*`: it must work while the rest of the worker is on
fire.
