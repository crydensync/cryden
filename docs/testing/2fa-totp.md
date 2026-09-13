# Manual testing: 2FA (TOTP)

## Fastest check — in-memory smoke test

No database needed:

```bash
go run ./cmd/smoketest/2fa-totp
```

This exercises the full flow against the in-memory store and prints a ✓/✗ line per step:

1. Sign up a user
2. Login before TOTP is enrolled → tokens issued directly
3. Enroll TOTP → get back an `otpauth://` URL
4. Login again *before confirming* → tokens still issued directly (an unconfirmed secret must never gate login)
5. Confirm enrollment with a real generated code
6. Login again → paused with `*auth.ErrTOTPRequired`, no tokens issued
7. Complete login with a correct code → tokens issued
8. Complete login with a wrong code → rejected
9. Complete login with a tampered/garbage pending token → rejected
10. Attempt to use a real access token in place of a pending token → rejected (catches the "typ" claim check specifically)
11. Disable TOTP → login goes back to issuing tokens directly

If every line prints ✓ and it ends with `ALL CHECKS PASSED`, the engine-level logic is sound.

## Full check — against real Postgres

1. Apply the migration:
   ```bash
   psql "$DATABASE_URL" -f store/postgres/migrations/0003_totp_secrets.up.sql
   ```
2. Set three env vars — `DATABASE_URL`, `JWT_SECRET`, and `ENCRYPTION_KEY` (must be different from `JWT_SECRET`, not reused).
3. Run the Postgres-backed version (see `cmd/smoketest/postgres-2fa-totp` if you kept it, or wire your own `main.go` following the `README.md` "Two-factor authentication" section — `Config.TOTP: postgres.NewTOTPStore(db)`).
4. Confirm in `psql` that a `totp_secrets` row was created on enroll, has `confirmed_at IS NULL` before confirmation, and is populated after.

## Unit tests

```bash
go test ./security/... ./auth/... ./store/...
```

Specifically relevant files:
- `security/totp_test.go` — code generation/validation, clock-skew window, wrong/expired code rejection
- `security/encryption_test.go` — encrypt/decrypt round-trip, different nonce per call, wrong key fails
- `auth/mfa_test.go` — enroll/confirm/disable, re-enrollment rejected once confirmed, wrong password blocks disable
- `auth/login_totp_test.go` — the full `Login` → `ErrTOTPRequired` → `CompleteLoginWithTOTP` handoff, plus the access-token-as-pending-token confusion test

## What "working" looks like, in plain terms

- An account with no TOTP enrolled logs in exactly as before — one call, tokens back immediately.
- Starting enrollment (`EnrollTOTP`) never affects login on its own — only a *confirmed* code does.
- Once confirmed, a correct password alone is no longer enough — `Login` returns an error, not tokens, and that error carries a short-lived pending token instead.
- That pending token is single-purpose: it only works with `CompleteLoginWithTOTP`, expires in 5 minutes, and a real access token can't be substituted for it.
- `DisableTOTP` requires the current password and immediately reverts the account to password-only login.
