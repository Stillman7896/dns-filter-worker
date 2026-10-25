# How it works

Design notes for people changing the code: the filter precedence chain, why the
storage is laid out the way it is, what the free plan's limits force, and how the
dashboard is served.

- [Precedence](#precedence)
- [The query path](#the-query-path)
- [Where the state lives](#where-the-state-lives)
- [Why not one key per rule](#why-not-one-key-per-rule)
- [Caching and read amplification](#caching-and-read-amplification)
- [The free-plan CPU budget](#the-free-plan-cpu-budget)
- [Matching cost](#matching-cost)
- [The dashboard is a static asset](#the-dashboard-is-a-static-asset)
- [Source layout](#source-layout)
- [Tests and CI](#tests-and-ci)

## Precedence

```
Response route — a fixed answer for the name + subdomains
  > Custom denylist
  > Custom allowlist
  > Remote blocklist (Hagezi pro-plus)
  > Blocked TLD (last-label match)                       [if tldBlock]
  > Blocked keyword (substring match)                    [if keywordBlock]
  > Regex rule (full-name pattern match)                 [if regexBlock]
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

A `@@` exception in the blocklist file cancels only the **blocklist** step: the
name falls through to the filters below it, and custom rules still outrank it
either way.

## The query path

1. Parse the DoH request (GET `?dns=` or POST body) and the client tag from
   `/dns-query/<tag>` or `?tag=`.
2. Load the effective configuration — settings, rules, filter lists, routes —
   from the isolate cache, refreshing a version stamp at most once per TTL.
3. Walk the precedence chain above and record which layer decided.
4. For anything reaching upstream: check the edge/isolate answer cache, then
   resolve over DoH (or ODoH), then apply answer-level rebinding protection.
5. Write the verdict to D1 and return a `application/dns-message` response.

The pipeline itself is pure logic in `filters.js` (`decide()`), which is what
makes it testable without a Worker, a KV namespace or a network.

## Where the state lives

| Store | Key | Contents |
|---|---|---|
| KV | `rules:data` | newline `kind<TAB>domain` |
| KV | `keywords:data` | newline keywords |
| KV | `regex:data` | newline regex patterns |
| KV | `tlds:data` | newline TLDs |
| KV | `routes:data` | newline `domain<TAB>type<TAB>value<TAB>ttl` |
| KV | `settings:main` | JSON of the toggles, subscription list and chosen provider |
| KV | `data:version` | timestamp bumped on **any** list write |
| D1 | `dns_logs` | one row per resolved query |

`data:version` is shared by every store: one tiny read per cache TTL tells all of
them whether their blob changed, so a warm query performs **zero** KV reads and a
cold one performs at most four. Writes are read-modify-write on the single blob
(1 read + 1 write), and bulk import uses `putBulk()` — one read and one write for
the whole batch instead of one pair per rule.

> **Known trade-off:** two writes racing on the same blob are last-write-wins, so
> a rule added during another isolate's save could be dropped. This only matters
> for concurrent editors; a single admin won't notice.

### Legacy one-key-per-rule layout

Earlier versions stored `rule:<domain>` keys. Those are migrated into
`rules:data` automatically on first load (read-only — they are left in place so
cleanup doesn't consume the free plan's write quota). How to reclaim the keys is
in [operations.md](operations.md#reclaiming-legacy-rule-keys).

## Why not one key per rule

**KV has *unlimited* keys per namespace**, so key count is never the limit. The
limits that actually matter are
[documented by Cloudflare](https://developers.cloudflare.com/kv/platform/limits):

| Limit | Value | Effect of one-key-per-rule |
|---|---|---|
| Keys / namespace | **Unlimited** | fine |
| **Operations / invocation** | **1,000** | `list()` + N×`get()` for 5k rules = **5,000 ops → hard failure** |
| Free: writes to *different* keys | **1,000 / day** | 5k rule edits/day exhausts it |
| Free: reads | 100,000 / day | N reads per cold start burns this quickly |
| Value size | 25 MiB | one blob holds ~1M domains |
| Writes to the *same* key | 1 / sec | irrelevant at one write per change |

## Caching and read amplification

- **Settings**: 30 s per-isolate TTL, zero KV reads on the hot path after the
  first load.
- **Lists**: stale-while-revalidate, one blob per list, refreshed when
  `data:version` moves.
- **Answers**: edge cache + isolate LRU, keyed by name, type, EDNS state and the
  current upstream configuration; positive answers honour record TTLs, negative
  answers are held for 60 s.
- **Config epoch**: changing the upstream provider/fallback, or the blocklist URL
  set, rotates the key so an answer produced under the old configuration is never
  replayed.

## The free-plan CPU budget

The 10 ms CPU budget is spent parsing blocklist documents, not answering
queries. That is why:

- a single document over `MAX_SOURCE_ENTRIES` (400,000) or `MAX_SOURCE_BYTES`
  (24 MB) is refused **before** its parse, and the previous copy keeps answering;
- a new subscription is refused while the merged entry total is already at
  `BLOCKLIST_ENTRY_LIMIT` (1,000,000);
- regex patterns are compiled once per list change rather than per query;
- the resolver returns `503` only when *no* document could be loaded at all.

Everything the dashboard needs while the worker is degraded (`/healthz`, the
reset hatch) lives outside the store and blocklist paths.

## Matching cost

`name.includes(kw)` over K entries on an L-character string is `O(K·L)` in the
worst case. With K = 50 entries and L = 60 chars that's ~3,000 char comparisons,
**well under 1 μs** — `String.prototype.includes` uses a fast search path in V8,
and for ASCII-only needles it degrades to near-`memchr` speed.

| Operation on the query path | Typical cost |
|---|---|
| Keyword match (50 entries) | **< 1 μs** |
| TLD `Set.has` | **~50 ns** |
| Blocklist walk (4 labels) | ~200 ns |
| KV read (when TTL expires) | 1–10 ms |
| **Network round trip to upstream** | **5–50 ms** |

Matching is ~10,000× cheaper than one network round trip, so it is effectively
free. The real scaling concern is **load time**, not match time — which is
exactly why lists are stored as one KV blob rather than one key per entry.

## The dashboard is a static asset

`ui/` is Vue 3 + Vite + UnoCSS source; `assets/` is the committed build output.
`wrangler` bundles `assets/` per the `[assets]` block (`binding = "ASSETS"`) and
the Worker serves it for any non-API, non-`/dns-query` path:

- `run_worker_first = ["/api/*", "/dns-query", "/dns-query/*", "/healthz", "/healthz/*", "/"]`
  lets the Worker answer those paths before falling through to the assets. The
  globs matter: `/api/` alone matches only the literal path, and a client tag
  (`/dns-query/<tag>`) needs its own rule.
- `not_found_handling = "single-page-application"` serves `index.html` for
  `/dashboard`, and `html_handling = "auto-trailing-slash"` keeps URLs stable.

Because the deployed Worker has no bundler, `assets/` must be rebuilt with
`npm run ui:build` and committed alongside any `ui/` change. `npm run
verify:assets` fails on drift, and CI runs it.

## Source layout

| File | Purpose |
|---|---|
| `worker.js` | Worker entrypoint, routing, full filter pipeline |
| `dns.js` | DNS wire parsing + response builders (Workers/Node) |
| `blocklist.js` | Remote list loader + subdomain matcher |
| `rules.js` | KV-backed allow/deny store (single blob) + subdomain matching |
| `lists.js` | Generic newline KV blob stores (keywords, TLDs, regex) + normalizers |
| `filters.js` | Query-path filter pipeline + `RegexEngine` (compiled-pattern cache) |
| `settings.js` | KV-backed persistent filter settings (toggles, provider) |
| `routing.js` | KV-backed response routes + record synthesis |
| `upstream.js` | Provider presets, resolution order, connection probe |
| `odoh.js` | Oblivious DoH client: HPKE (RFC 9180) + ODoH (RFC 9230) |
| `dashboard.js` | JSON API for rules/routes/logs/settings/session |
| `ui/` | Dashboard source (Vue 3 + Vite) |
| `assets/` | Dashboard build output, served as Worker assets |
| `schema.sql` | D1 schema for query audit logs |
| `wrangler.toml` | Worker config, assets, KV, D1, runtime vars |
| `tools/` | Repository tooling: inline-comment check, screenshot and brand renderers |

There are **no runtime dependencies**: the resolver is `fetch` plus Web Crypto.
That is a deliberate security property — keep it.

## Tests and CI

`node --test` runs the whole suite; the coverage floor is 85% lines and CI fails
below it. Two workflows jobs run on every push and pull request: `check`
(typecheck, lint, tests) and `assets` (the committed dashboard build matches
`ui/`).

`tools/check-inline.js` compiles the build output's inline theme script — the one
piece of JavaScript in `assets/index.html` that no bundler has parsed, and the
one that must run before first paint.
