# Manual testing: Passkeys (WebAuthn, second factor)

## Fastest check — in-memory smoke test

No database and no real browser needed — this uses a real simulated
authenticator (`github.com/descope/virtualwebauthn`), so it exercises
actual cryptographic verification, not just the rejection path a fake
response would be limited to:

```bash
go run ./cmd/smoketest/webauthn-passkeys
```

Walks: login before registration (direct), begin/finish registration
(rejecting a garbage response first), listing the passkey, login after
registration (paused, reports `Methods == ["webauthn"]`), the login
ceremony's own begin/finish round trip (rejecting a garbage response
and a tampered ceremony token), a successful completion, a real access
token rejected when used as a pending token, deleting the passkey
(wrong password rejected first), and login reverting to direct
afterward.

## Full check — against real Postgres

1. Apply the migration:
   ```bash
   psql "$DATABASE_URL" -f store/postgres/migrations/0004_webauthn_credentials.up.sql
   ```
2. Set `DATABASE_URL`, `JWT_SECRET`, `ENCRYPTION_KEY` (same key TOTP
   uses, if both are configured), plus real values for
   `WebAuthnRPID`/`WebAuthnRPDisplayName`/`WebAuthnRPOrigins` matching
   wherever you're actually testing from (e.g. RPID `localhost`,
   origin `http://localhost:3000` for local dev — WebAuthn requires
   either `https://` or `localhost` specifically, nothing else counts
   as a secure-enough origin).
3. This part genuinely needs a real browser and a real authenticator
   (Touch ID, Windows Hello, a physical key, or your OS's built-in
   passkey manager) — there's no way around that for a true end-to-end
   check, since the whole point of the ceremony is that the server
   can't forge a valid response. Wire `BeginRegisterPasskey`'s output
   to `navigator.credentials.create()` and `FinishRegisterPasskey`'s
   input from what that call resolves with; same pattern for
   `BeginWebAuthnLogin`/`navigator.credentials.get()`/
   `CompleteLoginWithWebAuthn`.
4. Confirm in `psql` that a `webauthn_credentials` row appears after
   registration, and that `last_used_at` updates after a login.

## Unit tests

```bash
go test ./security/... ./auth/... ./store/...
```

Specifically relevant files:
- `security/webauthn_test.go` — the `GoWebAuthnProvider` wrapper
  against a real simulated authenticator: registration produces a
  valid credential, a full login round trip succeeds and advances the
  signature counter, a garbage response is rejected
- `auth/webauthn_test.go` — `BeginRegisterPasskey`/
  `FinishRegisterPasskey`/`ListPasskeys`/`DeletePasskey`/
  `BeginWebAuthnLogin`/`CompleteLoginWithWebAuthn`, including garbage
  responses, a tampered ceremony token, wrong password on delete, and
  an account with no passkeys enrolled
- `auth/login_second_factor_test.go` — `Login`'s unified detection:
  WebAuthn-only reports `["webauthn"]`, TOTP+WebAuthn together report
  both, and neither enrolled still issues tokens directly

## What "working" looks like, in plain terms

- An account with nothing enrolled logs in exactly as before.
- Registering a passkey never affects login by itself — nothing
  changes until registration actually succeeds (a rejected/garbage
  response leaves the account exactly as it was).
- Once a passkey exists, `Login` pauses the same way TOTP does, and
  reports `"webauthn"` in `Methods` (alongside `"totp"` too, if both
  are enrolled).
- Completing the passkey ceremony is a nested begin/finish exchange —
  expect three calls total for a full login (`Login`,
  `BeginWebAuthnLogin`, `CompleteLoginWithWebAuthn`), not two like
  TOTP's `Login`/`CompleteLoginWithTOTP`.
- `DeletePasskey` requires the current password and immediately stops
  that specific passkey from being offered on the next login.
