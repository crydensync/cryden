# cryden — current state

Last updated: 2026-09-05 (by the session that built the SQLite storage
backend). Update this file's date and content every time a session
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


## Tier 3 — Infrastructure & Extensibility: IN PROGRESS (2 of 7)

Five items left. See `NEXT.md`.

### Item 12 — Argon2id hasher: DONE, branch `feat/argon2id-hasher`

A **second real implementation** of the existing `security.Hasher`, not
a replacement for bcrypt: `Hash`/`Compare` is still the whole surface
and nothing in `auth/` can tell which one it holds.

The design question the spec named — how the engine knows which
algorithm a stored hash used, for a table holding both — is answered by
**format sniffing**, as the spec suggested. Every hash names its own
algorithm and carries its own parameters, so verification is stateless:
no algorithm column, no backfill, and no column that can disagree with
the hash next to it.

Shipped as: `security/argon2idhasher.go` (`Argon2idHasher`,
`NewArgon2idHasher`, `Argon2idParams`, `DefaultArgon2idParams` = RFC
9106's second option 64 MiB/t=3/p=4, PHC encoding
`$argon2id$v=19$m=…,t=…,p=…$salt$key`), `security/multihasher.go`
(`MultiHasher`, `IdentifyHash`, `HashAlgorithm`), `Rehasher` in
`security/hasher.go` plus `BcryptHasher.NeedsRehash`, four new sentinels
in `security/errors.go`, `Config.Hasher`, `auth/rehash.go`, and
`store.EventPasswordHashUpgraded`. `engine.go` wraps whatever it holds
in a `MultiHasher` **unconditionally**. **No new module dependency** —
`x/crypto` was already required by bcrypt.

Decisions worth not re-deriving (full reasoning in `PROGRESS.md`):
`Rehasher` is an optional second interface, never part of `Hasher`, so a
host's own implementation keeps compiling and simply never upgrades;
`Config.Hasher` takes an already-constructed hasher like every store
(`BcryptCost` ignored when set), matching item 11's `RateLimiter`
precedent rather than an algorithm enum; upgrade-on-login is in scope,
because without it a mid-migration table never drains — accounts that
never change their password would never move — and is fire-and-forget,
so a store that refuses the write still lets the login through;
"out of date" means **weaker only**, never merely different, and
excludes `Parallelism`, a hardware-shaped knob that would otherwise
churn every hash on a machine change; the decoder rejects `t=0`/`p=0`
and caps `m=` at 4 GiB because `x/crypto` *panics* on the first two and
would try to allocate terabytes for the third.

Tests: `security/argon2idhasher_test.go` and
`security/multihasher_test.go` (83 cases in the package),
`auth/rehash_test.go` (7 funcs, four of them negative), 4 in
`config_test.go` including a facade-level mid-migration login. Smoke
test: `cmd/smoketest/argon2id-hasher` (120 checks over twelve sections,
no database, no server). Manual guide:
`docs/testing/argon2id-hasher.md`. One unrelated pre-existing test flake
was fixed in passing: `auth`'s login-timing regression test compared a
single bcrypt sample per path, which noise could breach; it now takes
the fastest of five. `PROGRESS.md` has the detail. Everything ran clean
here — `go build ./...`, `go vet ./...`, `go test ./...`, `gofmt -l` —
this item needed no external service, unlike item 11.

### Item 13 — SQLite storage backend: DONE, branch `feat/sqlite-store`

A **second real backend**, not a replacement: all nine `store.X`
interfaces plus `ai.QueryableStore` implemented against SQLite in a new
`store/sqlite` package. Nothing outside that directory changed — no
interface, no `store/postgres` file, no shared helper — and nothing in
`auth/`, `session/`, `security/` or the facade can tell which backend it
holds.

SQLite was confirmed rather than assumed: it is the only candidate that
changes *deployment shape* (a single file, no server) rather than vendor,
which is what a second backend is for, and it stresses the interfaces
hardest — no UUID function, no `RETURNING` on old versions, foreign keys
off by default.

Shipped as: `store/sqlite/` — `sqlite.go` (package doc, `formatTime`/
`parseTime`, `nullString`, `newID`), `migrate.go` (`Migrate`,
`CheckPragmas`, `ErrForeignKeysDisabled`, `ErrNoBusyTimeout`),
`migrations/0001_initial_schema.{up,down}.sql`, and ten stores:
`UserStore`, `SessionStore`, `AuditStore`, `VerificationStore`,
`OAuthStore`, `TOTPStore`, `WebAuthnStore`, `RecoveryCodeStore`,
`AnomalyStore`, `SafeQueryStore`. **No engine change at all** — no
`Config` field, no facade function: the stores satisfy interfaces that
already existed. `go.mod` gains `modernc.org/sqlite` as a
**test-and-smoketest-only** dependency.

Decisions worth not re-deriving (full reasoning in `PROGRESS.md`): the
package **imports no driver**, so a host picks mattn/modernc/ncruces and
the pragma DSN syntax is theirs, not ours; **timestamps are fixed-width
TEXT** (`2006-01-02T15:04:05.000000000Z07:00`, UTC, exactly 30 chars) so
lexicographic order equals chronological order, with columns declared
`TEXT` and never `DATETIME` because `mattn` would convert those to
`time.Time` and break every scan; **`UserStore.Delete` cascades by hand**
in a transaction because SQLite defaults `foreign_keys` *off*, and a
deleted account whose sessions survive keeps rotating refresh tokens —
`audit_events`/`login_attempts` get `user_id` NULLed instead, matching
`ON DELETE SET NULL`; `CheckPragmas` **reports** rather than sets,
because pragmas are per-connection and `*sql.DB` is a pool; `RETURNING`
avoided entirely (needs 3.35, bullseye ships 3.34.1) via `UPDATE` then
`SELECT` in one transaction, `COUNT(*) FILTER` → `COUNT(CASE WHEN …)`
(COUNT not SUM — SUM is NULL over zero rows), `gen_random_uuid()` →
`uuid.NewV7()`, `JSONB` → TEXT-holding-JSON passed as a `string` so
`json_*` can read it, `BYTEA` → BLOB, `ILIKE` → `LIKE`, and **upsert
needed no translation** (SQLite has had it since 3.24); store-assigned vs
caller-supplied timestamps follow Postgres exactly; `SafeQueryStore` must
be handed a **`mode=ro` handle**, not `PRAGMA query_only`, and that
handle — not the allowlist — is the real write boundary; **one migration
file**, since there was no deployed SQLite database to migrate
incrementally from.

Tests: eleven `_test.go` files, 53 funcs, using real files under
`t.TempDir()` rather than `:memory:` (a bare in-memory DSN belongs to one
connection, so a pool's second connection sees an empty schema). Smoke
test: `cmd/smoketest/sqlite-store` (160 checks over nine sections) —
writes real databases under a temp dir, because WAL, `busy_timeout` and
`mode=ro` only mean anything on a file, and its last section makes the
`:memory:` pool trap deterministic before showing `cache=shared` fix it.
Manual guide: `docs/testing/sqlite-store.md`. Everything ran clean here —
`go build ./...`, `go vet ./...`, `go test ./...`, `gofmt -l` — no
external service needed, unlike item 11.

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
- `feat/argon2id-hasher` — item 12, complete, 9 commits, branched from
  `feat/redis-rate-limiter` at `334c071`, the tip of the chain, so this
  branch carries items 8 through 12. Same adjacency caveat as the two
  above: `Config.Hasher` sits immediately below `Config.RateLimiter`, so
  lifting item 12 onto `main` alone means resolving that by hand. Unlike
  item 11 it adds no dependency and needs no external service to verify.
  Unmerged and unpushed.

- `feat/sqlite-store` — item 13, complete, 9 commits, branched from
  `feat/argon2id-hasher` at `ca80f05`, the tip of the chain, so this
  branch carries items 8 through 13. Unlike every item above it, this one
  touched **no engine file at all** — no `config.go`, no `engine.go` — so
  it has no adjacency to resolve and lifts onto `main` cleanly on its
  own. It does add a dependency, `modernc.org/sqlite`, but only for tests
  and `cmd/smoketest/sqlite-store`; `store/sqlite` itself imports no
  driver. Unmerged and unpushed.

Nothing else in flight. Each new session picks the top item off
`NEXT.md`, creates its own branch, and this section should be updated to
reflect that branch's existence and status before the session ends. If you start a session and this section already
lists an in-progress branch, that means a previous session didn't
finish cleanly — check that branch's own commits before assuming
anything about its state, and update this file to match reality once
you've looked.
