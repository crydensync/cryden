# cryden — current state

Last updated: 2026-09-03 (by the session that built Tier 1 + this
docs setup). Update this file's date and content every time a session
finishes an item — see `CLAUDE.md`'s end-of-session checklist.

## Tagged releases

- **v2.2.0** — Tier 1 complete. Currently the latest tag and the
  presumed base for all new work, unless a session's `NEXT.md` says
  otherwise.

## Tier 1 — Auth & Login: DONE (all shipped in v2.2.0)

TOTP (2FA), WebAuthn passkeys (second factor), magic-link login, more
OAuth providers (confirmed zero engine changes needed — provider is a
plain string), recovery/backup codes, breached-password check,
password policy. Plus a fix: `LoginWithOAuth` used to bypass the
second-factor gate entirely — now routes through the same
`completePrimaryAuth` helper every other primary auth method uses.

Do not re-verify, re-review, or re-read through this work. It's done.
If you find a real bug in it while working on something else, fix it
on its own small branch and note it in `PROGRESS.md` — don't treat
finding it as license to re-audit the rest.

## Tier 2 — Security & Monitoring: NOT STARTED

Four items, detailed specs in `NEXT.md`. One design decision already
made for item 8 (anomaly detection), via an earlier elicitation with
the project owner — **do not re-ask or re-derive this**, it's final:

- **Signals to evaluate**: new IP/device (vs. recent successful
  logins), failed-attempt velocity (per-user and per-IP), and
  token-reuse/session anomalies (reusing existing
  `token_reuse_detected` events + unusual concurrent-session counts).
  Impossible-travel (geo-distance) was explicitly deferred — it needs
  an external geo API, which breaks the "engine never calls the
  internet itself" rule; if it's ever built, it must be interface-
  only, host-supplied, same pattern as `BreachedPasswordChecker`.
- **On a flagged attempt**: record only, never block. Emit a new audit
  event with risk info; the host app decides what to do with it. No
  new sentinel error, no forced step-up, no hard block — those were
  all explicitly considered and rejected (false positives locking out
  real users was the deciding factor against hard-blocking; step-up
  2FA was rejected because it silently doesn't work for accounts with
  no second factor enrolled).
- **Storage**: a new `store.AnomalyStore` interface (with
  `store/memory` + `store/postgres` implementations + a migration),
  not a reuse of `AuditStore` alone and not the in-memory rate
  limiter — matches how every other Tier 1 feature was built, keeps
  queries indexed instead of scanning audit history, and avoids the
  in-memory rate limiter's known multi-instance correctness gap.

Items 9, 10, 11 (credential-stuffing detection, named/fingerprinted
sessions, Redis-backed rate limiter) have no prior design decisions
recorded — see `NEXT.md` for the level of detail available, make
reasonable calls on anything unspecified, note them in `PROGRESS.md`.

## Tier 3 — Infrastructure & Extensibility: NOT STARTED

Seven items. See `NEXT.md`.

## Tier 4 — AI-assisted admin features: NOT STARTED

Four items, all read-only/surface-only by explicit, non-negotiable
requirement — no automatic action, ever. See `NEXT.md`.

## Tier 5 — do not start without an explicit go-ahead from the project owner

Organizations/multi-tenancy, SSO via OIDC, SAML, RBAC/permissions,
data export/delete-my-data. If you reach the end of Tier 4 with
nothing left queued, stop and say so — don't proceed into Tier 5 on
your own initiative, this was stated explicitly in the original
project brief.

## Open branches / in-flight work

Nothing currently in flight as of this writing. Each new session picks
the top item off `NEXT.md`, creates its own branch, and this section
should be updated to reflect that branch's existence and status before
the session ends. If you start a session and this section already
lists an in-progress branch, that means a previous session didn't
finish cleanly — check that branch's own commits before assuming
anything about its state, and update this file to match reality once
you've looked.
