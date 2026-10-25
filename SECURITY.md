# Security policy

## Reporting a vulnerability

Use GitHub's private reporting flow:
<https://github.com/Stillman7896/sinkker/security/advisories/new>

Do not open a public issue for anything exploitable. Include the commit or
deployed version, a reproduction (a query, a request, or a config), and the
impact you believe it has. Expect an acknowledgement within a few days.

## Scope

Sinkker runs in two roles and both are in scope:

- **Resolver** — anything that lets a client bypass filtering, poison cached
  answers, or read another client's traffic through `/dns-query/*`.
- **Dashboard** — authentication bypass, session handling, injection through
  rule/route/blocklist input, or a stored payload that runs in an operator's
  browser.

Out of scope: a *deployment* that the operator misconfigured (a dashboard
password in a public repo, an unset `DASHBOARD_PASSWORD`, an untrusted upstream
they chose), and denylist/allowlist content itself — individual false positives
belong in an issue.

## Hardening expectations

- `DASHBOARD_PASSWORD` is the only secret. Set it with
  `wrangler secret put DASHBOARD_PASSWORD` — never commit it, and never put it in
  `[vars]` of a public repo.
- The dashboard is disabled (503 on `/api/*`) when that secret is unset.
- Sessions are a 24 h `HttpOnly` cookie and nothing else.
- `POST /healthz/reset` wipes KV configuration and is password-gated; treat that
  password as an admin credential.
- Keeping the dependency surface small is a security property of this project.
  New runtime dependencies need a strong justification; today the Worker has
  none — the whole resolver is undici `fetch` plus the Web Crypto API.
