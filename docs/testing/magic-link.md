# Manual testing: Magic-link (passwordless) login

## Fastest check — in-memory smoke test

No database and no real email provider needed:

```bash
go run ./cmd/smoketest/magic-link
```

Walks: requesting a link for a nonexistent email (silently returns
nil, sender never called), requesting for a real account (sender
receives the raw token), completing with the real token (issues
tokens), attempting to reuse the same token (rejected — single-use),
an expired token (rejected), and an account with TOTP enrolled pausing
with `*auth.ErrSecondFactorRequired` on completion instead of issuing
tokens directly.

## Full check — against real Postgres

No new migration — magic-link tokens reuse the existing
`verification_tokens` table (same one email-change confirmation
uses), distinguished by `purpose = 'magic_link'`.

1. Set `DATABASE_URL`, `JWT_SECRET`, and implement `notify.MagicLinkSender`
   against a real provider (or just print the token to your terminal
   for a first pass — the interface doesn't care).
2. Call `RequestMagicLink`, grab the token from wherever your sender
   implementation sent it, and call `CompleteMagicLink` with it.
3. Confirm in `psql` that a row appears in `verification_tokens` with
   `purpose = 'magic_link'`, and that `used_at` gets set after
   `CompleteMagicLink` succeeds — a second completion attempt with the
   same raw token should fail even before checking with the database
   directly.

## Unit tests

```bash
go test ./auth/...
```

Specifically relevant: `auth/magiclink_test.go` — covers sending only
for existing accounts (and never revealing which emails aren't
registered), single-use enforcement, expiry, a token from a *different*
purpose (e.g. email-change) correctly rejected as a login token, and
an account with TOTP enrolled correctly pausing for a second factor on
completion rather than logging straight in.

## What "working" looks like, in plain terms

- Requesting a link for an email that isn't registered behaves
  identically (from the caller's point of view — same nil return) to
  requesting one that is, except no email actually goes out. There's
  no way to tell the two cases apart from the return value alone.
- A requested link works exactly once. A second click — or any reuse
  of the same raw token — fails the same way an expired link does.
- An account with TOTP or a passkey enrolled does **not** get logged
  straight in by clicking the link — it pauses for the second factor,
  exactly like a correct password would.
- A token minted for something else (email-change confirmation) can
  never be used to log in, even if you have its raw value — the
  purpose is checked, not just "is this a valid unexpired token."
