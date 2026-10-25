# Contributing to Sinkker

Thanks for wanting to help. Bug reports, blockers of a specific client, new list
formats and documentation fixes are all welcome.

## Ground rules

- Be decent. [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies to every issue, PR
  and comment.
- Security issues do **not** go in the issue tracker — see
  [SECURITY.md](SECURITY.md).
- One topic per pull request. A PR that mixes a refactor with a feature will be
  asked to split.

## Setup

```sh
git clone https://github.com/Stillman7896/sinkker.git
cd sinkker
npm ci
git config core.hooksPath .githooks   # typecheck + lint on commit, tests on push
```

Node 22 or newer (see `.nvmrc`).

```sh
npm run ui:dev      # dashboard at http://localhost:5173 with a mock API
npm test            # node:test suite
npm run check       # typecheck + lint + tests with the coverage floor
```

Everything runs locally: the dashboard dev server answers `/api/*` from
`ui/mock/api.js`, so no Cloudflare account, KV or D1 is needed for UI work.

## The dashboard is a build artifact

`ui/` is the source, `assets/` is the committed Vite output that the Worker
serves. After any change under `ui/`:

```sh
npm run ui:build          # or: npm run verify:assets  (builds + fails on drift)
```

If you forget, CI fails on the asset diff — that is deliberate, the deployed
Worker has no bundler.

## Tests are the specification

The filter pipeline is pure logic in `filters.js` and is covered by
`test/filters.test.js`; the Worker's HTTP surface by `test/worker.test.js`.
Behaviour changes need a test that fails before the change and passes after.
The coverage floor is 85% lines and CI enforces it.

Prefer small, pure functions in the existing modules over a new abstraction.
Comments should explain *why* (a limit, a quirk, a trade-off) — the code says
what.

## Style

- ESLint is the arbiter: `npm run fix`.
- 2-space indent, single quotes, semicolons, 110-column soft wrap.
- UI copy is sentence case and plain English; the dashboard is read by people
  running a home network, not by DNS specialists.

## Screenshots and brand assets

Both are generated, never hand-edited:

```sh
npm run ui:dev &          # dashboard must be reachable
npm run screenshots       # -> docs/img/*.png
npm run brand             # -> brand/social-preview.png, ui/public/apple-touch-icon.png
```

`brand/*.svg` is the source of truth for the logo.

## Commits and releases

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
(`fix:`, `feat:`, `docs:`, `chore:`); the subject says what changed for a user.
Notable changes get an entry in [CHANGELOG.md](CHANGELOG.md) under *Unreleased*.
Maintainers tag releases as `vX.Y.Z` and the git tag is the release.
