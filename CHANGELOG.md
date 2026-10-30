# Changelog

Notable changes, newest first. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- **Blocked query response** setting (`blockedResponse`): pick what a stopped
  name answers with — `nxdomain` (default), `refused`, `null_ip`
  (`0.0.0.0` / `::`) or `nodata` — from Settings in the dashboard. It covers
  every block layer and the non-`IN` class reject, leaves response routes alone,
  and is part of the answer-cache key so a change takes effect on the next query.

## 2.0.0 — 2026-10-25

The community release. Renamed from `dns-filter-worker` to **Sinkker** and
published under the Unlicense.

### Added

- `LICENSE` (Unlicense), `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`,
  issue and pull-request templates.
- Logo and brand assets in `brand/` (`mark.svg`, `icon.svg`, `logo.svg`,
  `social-preview.png`), favicon and touch icon for the dashboard.
- Screenshots in `docs/img/`, regenerated with `npm run screenshots`.
- A "Deploy to Cloudflare" button and badges in the README; a documentation
  split that keeps the README a front page and moves the reference material into
  `docs/`.
- `npm run verify:assets` and an `assets` CI job: the committed dashboard build
  is now checked against `ui/` on every push (and `npm run ui:build` runs in CI,
  which it did not before).

### Changed

- **Breaking:** the Worker is named `sinkker` (`wrangler.toml`). An existing
  deployment keeps its old name and URL until it is re-deployed under the new
  name; set `DASHBOARD_PASSWORD` again with `wrangler secret put` if you do.
  KV and D1 bindings are unchanged, and the Worker migrates its own log columns
  on the first query.
- The npm package is named `sinkker`; the repository moved to
  `github.com/Stillman7896/sinkker` (GitHub redirects the old URL).
- The dashboard is branded Sinkker and its backup files download as
  `sinkker-<timestamp>.json`.
- The README is a front page: what it does, how to deploy it, where to read
  more. The precedence table, storage design and storage limits now live in
  [`docs/architecture.md`](docs/architecture.md), the settings and API reference
  in [`docs/configuration.md`](docs/configuration.md).

### Notes

- Earlier changes are in the git history and in the
  [releases page](https://github.com/Stillman7896/sinkker/releases); this is
  the first entry of this file.
