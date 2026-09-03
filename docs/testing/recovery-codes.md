# Manual testing: Recovery (backup) codes

## Fastest check — in-memory smoke test

No database needed:

```bash
go run ./cmd/smoketest/recovery-codes
```

Walks: generating codes fails for an account with no second factor
enrolled, enrolling TOTP then generating a real batch of 10 unique
codes, logging in and completing with a real code, reusing the same
code (rejected), a wrong code (rejected), regenerating invalidating
the previous batch, and — the important safety property — disabling
the account's only real second factor and confirming any leftover
recovery codes no longer gate login at all.

## Full check — against real Postgres

1. Apply the migration:
   ```bash
   psql "$DATABASE_URL" -f store/postgres/migrations/0005_recovery_codes.up.sql
   ```
2. Generate a batch for a test account with TOTP already confirmed,
   note the codes, then confirm in `psql` that `recovery_codes` has 10
   rows with `used_at IS NULL`.
3. Complete a login with one of them, confirm `used_at` gets set on
   exactly that row and no others.
4. Regenerate, confirm the table now only has the new 10 rows — the
   old ones are gone, not just marked used.

## Unit tests

```bash
go test ./auth/...
```

Specifically relevant: `auth/recoverycodes_test.go` — covers rejecting
generation with no second factor enrolled, producing 10 unique codes,
regeneration invalidating the previous batch, single-use enforcement,
case/whitespace-insensitive matching (people retype these by hand), a
wrong code, and the two `Login`-level safety tests: `"recovery_code"`
is only ever advertised alongside a real factor (`"totp"` or
`"webauthn"`), and codes left over after disabling the real factor
never gate login on their own.

## What "working" looks like, in plain terms

- Generating codes for an account with no TOTP/passkey fails outright
  — there's nothing for them to be a fallback for.
- The 10 codes are shown exactly once. There is no way to view them
  again later — only regenerate a fresh batch (which invalidates the
  old one).
- Each code works exactly once, the same way a magic link does.
- Generating a new batch kills every code from the old one immediately
  — used or not.
- The property that actually matters most: if someone disables their
  TOTP (or removes their only passkey) but never explicitly cleared
  out their recovery codes, those codes must NOT keep working as a
  standalone login gate. Confirm this directly — enroll TOTP, generate
  codes, delete the TOTP secret, then log in and confirm you get
  tokens straight back with no second-factor pause at all.
