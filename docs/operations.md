# Deploy, upgrade, troubleshoot

- [Deploy](#deploy)
  - [One click](#one-click)
  - [Manual, in five commands](#manual-in-five-commands)
- [Point your devices at it](#point-your-devices-at-it)
- [Verify](#verify)
- [Upgrading](#upgrading)
- [Reclaiming legacy rule keys](#reclaiming-legacy-rule-keys)
- [Backups](#backups)
- [Troubleshooting](#troubleshooting)

## Deploy

Requirements: a Cloudflare account (the free plan is the target), and either a
GitHub/GitLab account or Node 22+ with `wrangler` locally. Two KV namespaces and
one D1 database are the only resources; both are created for you on the one-click
path and can also run without logging at all.

### One click

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Stillman7896/sinkker)

The button clones this repository into your GitHub account, provisions the KV
namespace and D1 database, and deploys the Worker. You are asked for
`DASHBOARD_PASSWORD` during setup — pick a strong one, it is the only credential
the project has. After the first deploy, push to the new repository with Workers
Builds and every change redeploys itself.

### Manual, in five commands

```sh
npm i -g wrangler
wrangler login

# 1. KV namespace (rules, lists, settings) — --update-config writes the id into wrangler.toml
wrangler kv namespace create RULES --binding RULES --update-config
wrangler kv namespace create RULES --preview   # preview_id for `wrangler dev`, if you want one

# 2. D1 database (query logs) — optional but enables the Logs tab
wrangler d1 create dns-logs --binding LOGS --update-config
wrangler d1 execute dns-logs --remote --file=./schema.sql

# 3. Dashboard password
wrangler secret put DASHBOARD_PASSWORD

# 4. Ship it
npm run deploy
```

Notes:

- The ids committed in `wrangler.toml` belong to the maintainer's account.
  `--update-config` replaces them with yours as the resources are created, so run
  steps 1 and 2 before the first `npm run deploy`.
- Skipping D1 is supported: delete the `[[d1_databases]]` block and the dashboard
  keeps working — the log endpoints answer `501 no_d1` and the Logs tab is empty.
  Skipping KV is also supported: rules, settings and filter lists are then
  in-memory defaults and the dashboard has nothing to save into.
- The Worker creates the log table and its columns itself on the first query, so
  `wrangler d1 execute ... --file=./schema.sql` is only a convenience.

## Point your devices at it

The endpoint is always your own origin:

```
https://<your-worker>.workers.dev/dns-query
```

- **Browser**: Settings → Privacy → DNS over HTTPS → custom, paste the URL.
- **Router / AdGuard Home / dnsmasq upstream**: same URL wherever a DoH endpoint
  is accepted. On systems that only speak plain DNS, run `cloudflared` locally
  and point them at its listen address.
- **Per-device tag**: `https://<worker>/dns-query/laptop` (or `?tag=laptop`) puts
  that device's queries in their own bucket on the **Logs** page. The dashboard's
  Overview builds a ready-to-paste URL.
- **Command line** (a real `example.com` A query, base64url-encoded):

```sh
curl -sS -H 'accept: application/dns-message' \
  'https://<worker>/dns-query?dns=q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' | xxd
```

## Verify

`/healthz` is the health surface — stats, the settings actually in force, the
resolved upstream and blocklist URLs, and a `problems[]` list when something is
degraded (HTTP 503 in that case). It exposes no secrets, so it is safe to open
and to paste into an issue report. `dashboardConfigured` tells you whether
`DASHBOARD_PASSWORD` reached the Worker.

## Upgrading

Deploy the new code; KV and D1 need no migration. Two things to know:

- **The Worker is named `sinkker`** since v2.0.0. If you deployed earlier
  versions, your Worker is still called `dns-filter-worker` and keeps its old
  URL: running `npm run deploy` now creates a *second* Worker under the new name.
  Either keep the old one (set `name` back in `wrangler.toml`) or re-deploy under
  the new name, re-run `wrangler secret put DASHBOARD_PASSWORD`, and point your
  clients at the new URL before deleting the old Worker. KV and D1 bindings are
  shared — the ids in `wrangler.toml` do not change.
- Legacy `rule:<domain>` KV rows are migrated into `rules:data` on first load and
  left in place (read-only), so a free-plan write quota is never spent on
  cleanup.

## Reclaiming legacy rule keys

Only needed if you want the old keys gone:

```sh
wrangler kv key list --namespace-id=<ID> --prefix="rule:" > legacy-rules.json  # inspect first
wrangler kv bulk delete legacy-rules.json --namespace-id=<ID> --force          # then remove
```

## Backups

The dashboard's **Backup** tab exports the whole configuration (settings, rules,
routes, keywords, TLDs, regex, subscription list) as a timestamped JSON file, and
imports one back. The query log is not part of it — that lives in D1 and is
managed from the **Logs** tab.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Dashboard says "no dashboard password" and every `/api/*` call is 503 | `DASHBOARD_PASSWORD` is unset. Run `wrangler secret put DASHBOARD_PASSWORD`. Filtering works without it. |
| `/healthz` answers 503 with `problems[]` | A blocklist subscription failed or exceeded its caps (see the `total`/limits shown on **Filter lists**). The previous copy keeps answering; fix or remove the offending subscription, or use **Reset worker**. |
| The dashboard cannot load at all, or shows the failure screen | The Worker is down (crash, quota, or a configuration that exceeds the CPU/memory budget). The screen prints the `curl` reset command; the same command is in [configuration.md](configuration.md#escape-hatch-healthzreset). |
| A domain resolves although it should be blocked | Check the precedence chain in [architecture.md](architecture.md#precedence): an allow rule or a route outranks the blocklist. `/api/test` runs the real pipeline for one name and reports the layer that decided; the **Probe** tab does the same from the UI. |
| A domain is still blocked although it is allowlisted | `@@` exceptions and allow rules outrank the blocklist, but a *route* outranks everything. Also confirm the client is not using another resolver (a cached answer, or a second DNS server on the network). |
| Settings or new rules do not take effect immediately | Each isolate caches settings for 30 s. A save applies to the isolate that wrote it at once; every other colo follows within ~30 s. |
| Saving settings answers 503 "settings could not be read from KV" | The Worker could not read `settings:main`, so it refused to overwrite it. Nothing was written — retry; if it persists, check the KV binding. |
| Queries fail with SERVFAIL with ODoH configured | The relay is unreachable or its URI template is wrong. Run **Test connection** in Settings; a relay is required and is never defaulted. |
| Free-plan writes start failing | KV allows 1,000 writes/day to different keys on the free plan. Bulk import (`/api/rules/bulk`, the dashboard's import) writes one blob instead of one key per rule. |
| A host resolves to a private address | `rebindProtection` is on: private answers are blocked at the answer level. Add the name as an allow rule (or a route) if it is intentional. |

When reporting a problem, include the commit or version, the `/healthz` JSON and
the client you used — the
[bug report template](https://github.com/Stillman7896/sinkker/issues/new?template=bug_report.yml)
asks for exactly that. Never paste `DASHBOARD_PASSWORD` or a session cookie.
