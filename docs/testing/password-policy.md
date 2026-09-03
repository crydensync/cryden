# Manual testing: Password policy

## Fastest check — in-memory smoke test

No database needed:

```bash
go run ./cmd/smoketest/password-policy
```

Walks: the zero-value `Config.PasswordPolicy` (via `cryden.New`)
applying `security.DefaultPasswordPolicy` automatically, a password
below the default minimum length rejected, a password over 72 bytes
rejected (bcrypt's real limit), a custom stricter policy (uppercase +
digit required) rejecting a password missing both and reporting BOTH
violations at once, and a password that satisfies a custom policy
succeeding.

## Unit tests

```bash
go test ./security/... ./auth/...
```

Specifically relevant:
- `security/passwordpolicy_test.go` — `Validate` reporting every
  violated rule together (not just the first), `MaxLength: 0` meaning
  no upper bound, symbol detection, and the default policy's actual
  bounds (8 min, 72 max)
- `auth/passwordpolicy_test.go` — policy enforcement wired into
  `SignUp`/`ChangePassword`, including the ordering guarantees (policy
  before breach check, current-password check before new-password
  policy check)

## What "working" looks like, in plain terms

- Leave `Config.PasswordPolicy` unset entirely and you still get a
  real minimum (8 characters) — this is the one feature in this engine
  with no "off by default" state, unlike TOTP/WebAuthn/recovery codes.
- A password failing multiple rules at once (too short AND missing a
  required character class) reports every broken rule together, not
  one at a time.
- The violation codes (`min_length`, `require_uppercase`, etc.) are
  stable strings meant for your own UI to translate into user-facing
  copy — the engine doesn't supply display text for these any more
  than it supplies email body text for `EmailSender`.
- A password over 72 bytes is rejected with a clean policy violation,
  not a bcrypt library error surfacing from inside `Hash`.
