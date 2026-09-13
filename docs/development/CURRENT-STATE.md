# cryden — current state

Last updated: 2026-09-05 (by the session that built the Redis-backed
rate limiter). Update this file's date and content every time a session
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

## Tier 2 — Security & Monitoring: DONE (4 of 4)

### Item 8 — anomaly detection: DONE, branch `feat/anomaly-detection`

Not merged — the human reviews and pushes. Do not re-verify or
re-review this; see the note at the end of the Tier 1 section, it
applies here too.

Shipped as: `security/anomaly.go` (pure logic — `AnomalySignal`,
`LoginAttemptContext`, `AnomalyObservations`, `AnomalyThresholds`,
`DefaultAnomalyThresholds`, `Evaluate`, `JoinAnomalySignals`),
`auth/anomaly.go` (the storage-reading pass plus the exported
`RecordLoginAttempt` that failure paths call), `store.AnomalyStore`
with `store/memory` + `store/postgres` implementations, migration
`0006_login_attempts`, the `anomaly_detected` audit event type, and
`Config.Anomalies` / `Config.AnomalyThresholds`.

Six signals ship, not three: the spec's "new IP/device" and
"token reuse / session anomalies" each split into two, because a known
device on a new IP and a new device on a known IP mean different
things, and so do a replayed refresh token and an unusual live-session
count. Codes are `new_ip`, `new_device`, `user_failure_velocity`,
`ip_failure_velocity`, `token_reuse`, `concurrent_sessions`.

Detection runs inside `completePrimaryAuth`, so all three primary auth
paths (password, magic-link, OAuth) are covered by one call. It is
report-only, nil-safe, and degrades to "no evidence" on any storage
error. Tests: `security/anomaly_test.go` (12, no store at all),
`auth/anomaly_test.go` (13, through the real flows),
`store/memory/anomaly_store_test.go` (6), plus 4 in `config_test.go`.
Smoke test: `cmd/smoketest/anomaly-detection` (54 checks). Manual
guide: `docs/testing/anomaly-detection.md`.

### Item 9 — credential-stuffing detection: DONE, branch `feat/credential-stuffing`

Not merged — the human reviews and pushes. Same "don't re-verify" note
as everything above.

The attack is one IP trying one leaked password against many different
accounts, which per-account lockout structurally cannot see: lockout
counts failures against one account, and a spray gives each account
exactly one. Built as a second reading of item 8's `login_attempts`
history, not a second tracking system.

Shipped as: `security/stuffing.go` (pure logic —
`CredentialStuffingObservations` with its `Breadth()`,
`CredentialStuffingThresholds`, `DefaultCredentialStuffingThresholds`,
`Evaluate`, and two signals reusing item 8's `AnomalySignal` type so
`JoinAnomalySignals` serves both), `auth/stuffing.go` (the
storage-reading pass plus the cooldown check),
`store.AnomalyStore.CountTargetsForIP` returning a new
`store.IPTargetCounts` in both `store/memory` and `store/postgres`, the
`credential_stuffing_detected` audit event type, and
`Config.CredentialStuffingThresholds`. **No migration** — the query
reads the same rows and the same partial index
(`idx_login_attempts_ip_failures`) `CountFailuresForIP` already used.

Two signals: `account_spray` (breadth over threshold) and
`unknown_account_spray`, a qualifier that never fires alone and means
most of the spray hit addresses with no account here. Breadth is
distinct known accounts plus unknown-target failures, because
`store.LoginAttempt` never records which email was tried and there is
nothing to de-duplicate unknown targets on.

Runs on failures (inside `recordLoginFailure`, where a spray is visible
at all) as well as successes (inside `completePrimaryAuth`, where a
spray that landed is visible) — both *after* the attempt is recorded, so
the burst being judged includes it. That is the opposite ordering from
item 8, which gathers a baseline before recording. Report-only,
nil-safe, degrades to "no evidence" on any storage error, and `Cooldown`
collapses a sustained spray into one event per IP via a bounded
newest-first `SearchByType` scan that fails open.

Tests: `security/stuffing_test.go` (10, no store at all),
`auth/stuffing_test.go` (9, through the real flows — including that 12
failures against ONE account is deliberately not flagged), 2 more in
`store/memory/anomaly_store_test.go`, 3 more in `config_test.go`. Smoke
test: `cmd/smoketest/credential-stuffing` (99 checks). Manual guide:
`docs/testing/credential-stuffing.md`.

### Item 10 — named/fingerprinted sessions: DONE, branch `feat/named-sessions`

Not merged — the human reviews and pushes. Same "don't re-verify" note
as everything above.

`NEXT.md` called this the vaguest item in the backlog and expected a
documented judgment call. The call: a session's label is **computed on
read** from the `IP` and `UserAgent` `store.Session` already carries.
No column, no table, **no migration** — so every session ever recorded
gets a label the first time it is listed, and improving the parser later
improves old sessions retroactively. `PROGRESS.md` has the full
reasoning, including the alternatives rejected.

Shipped as: `security/useragent.go` (pure parsing — `Device` with
`Browser`/`OS`/`Form`, the `FormDesktop`/`FormMobile`/`FormTablet`/
`FormBot` constants, `Device.String()`, `Device.IsZero()`,
`ParseUserAgent`), `security/geolocation.go` (`Location` with
`String()`/`IsZero()`, plus the `IPGeolocator` interface — **zero
shipped implementations**), `session/named.go` (`NamedSession` embedding
`store.PublicSession`, the exported `Label` composer, and `ListNamed`),
the `ListNamedSessions` facade with a `cryden.NamedSession` alias, and
`Config.Geolocator`. No store interface, migration or query was touched.

The two halves are deliberately asymmetric: parsing ships as real engine
code because it needs nothing the engine doesn't already hold, while
placing an IP ships as an interface only because it means an outbound
call or a licensed database — the `BreachedPasswordChecker` rule. Left
nil, labels are device-only and nothing else changes; a geolocator error
costs a label, never the listing; it is asked once per distinct IP per
call.

Tests: `security/useragent_test.go` (3 funcs, 23 authentic-User-Agent
subtests), `security/geolocation_test.go` (2), `session/named_test.go`
(8), plus 2 in `config_test.go` and 3 in `new_facade_test.go`. Smoke
test: `cmd/smoketest/named-sessions` (42 checks). Manual guide:
`docs/testing/named-sessions.md`.

### Item 11 — Redis-backed rate limiter: DONE, branch `feat/redis-rate-limiter`

A **second real implementation** of the existing `security.RateLimiter`,
not a new interface: the in-memory one keeps its counters in a Go map,
which is correct for exactly one process — three replicas keep three
maps, so a configured limit of 10 lets 30 through.

Shipped as: `security/redisratelimiter.go` (`RedisRateLimiter`,
`NewRedisRateLimiter`, `NewRedisRateLimiterWithPrefix`,
`DefaultRedisKeyPrefix = "cryden:ratelimit:"`), three new sentinels in
`security/errors.go`, and `Config.RateLimiter` — injected already
constructed, like every store, so the engine never dials Redis nor owns
its lifecycle. `engine.go` falls back to the in-process default only
when that field is nil. Nothing in `auth/` changed or can tell which
implementation it holds.

Decisions worth not re-deriving (full reasoning in `PROGRESS.md`):
`github.com/redis/go-redis/v9`, injected as its own `redis.Scripter`
interface so Client/ClusterClient/Ring/UniversalClient all work and
`redis.NewScript`'s EVALSHA→EVAL fallback is reused rather than
reimplemented; one Lua script per `Allow` because INCR and PEXPIRE
apart lets two replicas each arm their own window; `PEXPIRE` only when
`INCR` returns 1 (or `PTTL` reports none) so a denied client's own
retries cannot push its window out; exactly one key per call, so
Cluster needs no special case; windows under 1ms rejected rather than
rounded, the single place the two implementations are not
interchangeable. Fail-closed is unchanged and now load-bearing — all
three call sites already propagate a limiter error, so Redis becomes a
hard dependency of SignUp/Login/RequestMagicLink; documented, with a
fail-open wrapper left to the host.

Tests: `security/redisratelimiter_test.go` (14 funcs over a fake that
models the script), plus 3 in `config_test.go` and 1 in
`new_facade_test.go`. Smoke test: `cmd/smoketest/redis-rate-limiter`
(58 checks over ten scenarios) — runs against an in-process stand-in by
default, and against a real server with `REDIS_ADDR` set, which is the
mode that actually executes the Lua. **No Redis server was reachable in
the build environment**, so the Lua itself is so far verified only
against that stand-in; one `docker run` closes the gap. Manual guide:
`docs/testing/redis-rate-limiter.md`.

#### Item 8's recorded decisions, kept for reference

What the shipped anomaly-detection code implements. **Do not re-ask or
re-derive it**:

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
  As built, that interface is `RecordAttempt`, `ListRecentSuccesses`,
  `CountFailuresForUser` and `CountFailuresForIP` over one
  `login_attempts` table with three partial indexes — plus
  `CountTargetsForIP`, added by item 9 above against the same table.


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

- `feat/anomaly-detection` — item 8, complete, 6 commits, branched from
  `main` at `5b6c7f5`. Unmerged and unpushed, awaiting the human's
  review.
- `feat/credential-stuffing` — item 9, complete, 6 commits, branched
  from `feat/anomaly-detection` at `d30ed74` rather than from `main`,
  because item 9 extends item 8's store and is not reviewable without
  it. So this branch contains item 8's six commits too: merging it
  lands both items, and merging item 8 first makes this one a clean
  fast-forward. Unmerged and unpushed.
- `feat/named-sessions` — item 10, complete, 7 commits, branched from
  `feat/credential-stuffing` at `36690bf`, the tip of the chain, so this
  branch carries items 8, 9 and 10. Item 10 has no functional dependency
  on the earlier two — it reads no store or config they added — but its
  `config.go`/`engine.go` additions sit directly above theirs, so lifting
  it onto `main` alone means resolving that adjacency by hand. Unmerged
  and unpushed.
- `feat/redis-rate-limiter` — item 11, complete, 6 commits, branched
  from `feat/named-sessions` at `345b2d7`, the tip of the chain, so this
  branch carries items 8, 9, 10 and 11. Item 11 has no functional
  dependency on any of them, but it adds a `config.go`/`engine.go` field
  in the same region they did, so the same by-hand adjacency applies if
  it is lifted onto `main` alone. It is also the only item so far that
  adds a **direct third-party dependency** (`go-redis`) to `go.mod`.
  Unmerged and unpushed.

Nothing else in flight. Each new session picks the top item off
`NEXT.md`, creates its own branch, and this section should be updated to
reflect that branch's existence and status before the session ends. If you start a session and this section already
lists an in-progress branch, that means a previous session didn't
finish cleanly — check that branch's own commits before assuming
anything about its state, and update this file to match reality once
you've looked.
