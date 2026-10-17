# Bug Report — Dashboard UI Syntax Error

**Status:** Open (blocking the toast PR)
**Component:** `assets/index.html` inline `<script>`
**Detected:** during `node --check` / `new Function(...)` validation of the inline script
**Error:** `SyntaxError: missing ) after argument list`

## Reproduction

```sh
node -e "const s=require('fs').readFileSync('assets/index.html','utf8'); \
new Function(s.match(/<script>([\\s\\S]*?)<\\/script>/)[1])"
```

## Diagnosis attempts (all inconclusive)

| Method | Result | Notes |
| --- | --- | --- |
| paren count (naive, no string skip) | 3 excess | counts parens inside strings |
| paren count (skips strings, regex-greedy) | 1 excess | regex `/g` confuses scanner |
| line bisect with `new Function` | "BROKEN" at line 5 | false positive — declarations |
| `node --check` on extracted script | line 495 `};` | message line ≠ true culprit |
| new Function | `missing ) after argument list` | no line info |

## Suspected root cause

A `(` is left unclosed somewhere in the script, and the parser only
surfaces the error at the next top-level `};`. Hand-audit of every
modified region (login, add, bulk-add, rule delete, log allow/deny/del,
settings save) found each balanced under inspection, so the imbalance
might be in unmodified code OR the only reliable fix is a proper
tokenizer/AST. The scanner is blocked by regex literals like
`/[&<>"']/g` which it misreads as string openers, so auto-location is
untrustworthy.

## Next step for reviewer

- Run the repro above after fixing.
- Prefer a tokenizer that treats `/.../` after an operator as regex, or
  temporarily comment out the `escapeHtml` regex to see if balance flips.
- Only then land the toast/loading changes (see `git diff assets/index.html`).
