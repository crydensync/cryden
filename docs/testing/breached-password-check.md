# Manual testing: Breached-password check

## Fastest check — in-memory smoke test

No database and no real HIBP call needed:

```bash
go run ./cmd/smoketest/breached-password-check
```

Uses two tiny local fake checkers (not a real HIBP client — see below
for why) to demonstrate the actual contract: a confirmed breach
rejects the password with `auth.ErrPasswordBreached`, a checker error
fails open (signup/change still succeeds), and the checker is never
called at all if the password already fails the policy check first.

## Why the smoke test doesn't call the real HIBP API

`security.BreachedPasswordChecker` ships zero implementations
on purpose (see the README) — this is the one place in the engine
where an outbound network call is the entire point, so it's left
entirely to the consuming app. A "smoke test" that itself shipped a
real HIBP client would quietly become a shipped implementation,
undermining that design choice. If you want to verify against the
real API:

1. Implement the interface against `https://api.pwnedpasswords.com/range/{prefix}`
   (see the README's example implementation).
2. Wire it into `Config.BreachedPasswordChecker`.
3. Try signing up with a genuinely breached password (e.g. `password123`,
   `qwerty123456` — anything you'd find in a "worst passwords" list)
   and confirm you get `auth.ErrPasswordBreached`.
4. Try a random, never-used string — confirm it passes.
5. Point the checker at an unreachable URL temporarily and confirm
   signup still succeeds (fail-open).

## Unit tests

```bash
go test ./auth/...
```

Specifically relevant: `auth/passwordpolicy_test.go` — covers a
confirmed breach rejecting SignUp/ChangePassword, a checker error
failing open, the checker never being called when the (cheaper, local)
policy check already failed, and the rejection being recorded as a
`password_breach_rejected` audit event.

## What "working" looks like, in plain terms

- A password the checker confirms as breached is rejected outright,
  on both signup and password change.
- If the checker itself fails (network error, timeout, HIBP down),
  the action still succeeds — a third-party API's uptime should never
  be able to block your users from signing up or changing their
  password.
- The breach check is skipped entirely if the password already
  violates the configured policy — no reason to make an external call
  for input you were already going to reject.
- On `ChangePassword` specifically: the *current* password is verified
  before the *new* password's breach status is checked — someone who
  doesn't already know the current password never learns anything
  about whether their guessed new password would pass.
