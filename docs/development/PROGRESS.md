# cryden — progress log

Append-only. Newest entry at the bottom. One entry per session, added
right before that session stops — see `CLAUDE.md`'s end-of-session
checklist. Keep entries short: what got built, the branch, one line on
any assumption made. This is a log, not a design document — detailed
reasoning belongs in commit messages and code comments, not here.

---

## 2026 — Tier 1 (prior work, summarized retroactively)

Built across multiple sessions before this file existed: TOTP 2FA,
WebAuthn passkeys (second factor), magic-link login, OAuth provider-
agnostic confirmation (no engine changes needed for new providers),
recovery codes, breached-password checking, password policy. Plus a
fix for `LoginWithOAuth` bypassing the second-factor gate. Tagged as
**v2.2.0**. Full detail in each feature's git history and
`docs/testing/*.md` — not repeated here.

## 2026-09-03 — Development workflow setup

Added `CLAUDE.md` + this `docs/development/` structure
(`CURRENT-STATE.md`, `NEXT.md`, `CRYDEN-REVIEW.md`, `PROGRESS.md`) so
future terminal sessions read state from files instead of re-deriving
it through conversation each time. No engine code changed. Branch:
none — these are meta/process files, human will decide where they
land (likely directly reviewed and committed to whatever branch/main
state the human already has locally, since prior sessions' branches
were merged outside of this file-writing session).

---

<!-- New entries go below this line. -->

## 2026-09-04 — Anomaly detection (item 8)

Branch: `feat/anomaly-detection` (6 commits, unmerged, unpushed).

Built: report-only login anomaly detection. Pure threshold arithmetic
in `security/anomaly.go`, the storage-reading pass in
`auth/anomaly.go`, a `store.AnomalyStore` over a new `login_attempts`
table (memory + postgres + migration `0006`), an `anomaly_detected`
audit event, and `Config.Anomalies` / `Config.AnomalyThresholds`.
Detection is called once from `completePrimaryAuth`, which covers
password, magic-link and OAuth login together. 35 Go tests, a 54-check
smoke test at `cmd/smoketest/anomaly-detection`, and
`docs/testing/anomaly-detection.md`.

Assumptions made (spec left these open):

- **Config shape.** `NEXT.md` said "`Config.AnomalyDetector` or
  similar — you decide." I split it the way the codebase already
  splits this kind of thing rather than inventing a third pattern: an
  injected optional store (`Config.Anomalies`, nil ⇒ feature off, like
  `TOTP`/`WebAuthn`/`RecoveryCodes`) plus a plain config struct
  (`Config.AnomalyThresholds`, whole-struct zero ⇒ defaults, like
  `PasswordPolicy`). No detector interface: there is nothing here a
  host app would want to swap that the thresholds don't already cover,
  and an interface would have dragged `store` into `security`.
- **Six signals, not three.** The spec's "new IP/device" and "token
  reuse / session anomalies" each carry two distinct meanings, so each
  became two signals. A known device on a new IP is travel; a new
  device on a known IP is more often a second party. A replayed
  refresh token and an unusual live-session count are equally
  unrelated. Merging either pair would have made the metadata
  ambiguous for exactly the monitoring it exists to feed.
- **Baseline is successes only.** `AnomalyStore.ListRecentSuccesses`
  deliberately ignores failures. If failures fed the known-IP list, an
  attacker would establish their own address as familiar just by
  failing a few times first.
- **First login is never flagged.** `HasLoginHistory` suppresses
  new_ip/new_device when the account has no prior success. Otherwise
  every account's first login is an anomaly, which is noise.
- **A separate `TokenReuseLookback` (24h) alongside `Window` (15m).**
  Failure velocity is a burst happening now; a stolen refresh token
  replayed this morning still matters this afternoon. One duration
  could not serve both, and unbounded would flag every login the
  account ever makes again.
- **Token-reuse history is a bounded 100-event scan** of the user's
  audit log, because `AuditStore` has no by-user-and-type query
  (`ListByUser` is per-user, `SearchByType` is system-wide). A user
  with more than 100 events since their last reuse event misses the
  signal. Acceptable for a report-only annotation; adding an
  `AuditStore` method for it would have widened the item.
- **Sequencing.** Observations are read before the current attempt is
  recorded, so an attempt can never appear in its own baseline.
- **Storage errors degrade to "no evidence,"** never to "everything is
  unfamiliar" — the latter would flag every login during an outage.

Verification: `go build ./...`, `go vet ./...` and `go test ./...` all
run clean here with `GOTOOLCHAIN=go1.25.11 GOPROXY=off` (the module
cache has every dependency; only the toolchain download fails without
network, and `/usr/bin/go` is 1.22.2 while `go.mod` needs 1.25.0 —
hence the explicit `GOTOOLCHAIN`). The smoke test runs and passes all
54 checks. Postgres was not exercised — no database in this
environment; migration `0006` and `store/postgres/anomaly_store.go`
are reviewed-and-compiled only, and section 9 of the manual test guide
covers what to check against a real one.

Noted in passing, not fixed: `TestLogin_NonexistentUserTimingMatches`
`WrongPassword` in `auth/` is timing-based and flaked once when the
full suite ran packages in parallel (ratio 0.35), then passed on three
consecutive full runs and five isolated ones. Pre-existing and
unrelated to this item — it compares two bcrypt durations and is
sensitive to CPU contention. Worth its own small branch if it recurs.

Next in queue: item 9, credential-stuffing detection. `login_attempts`
already holds the data it needs; `NEXT.md` has the updated spec.

## 2026-09-04 — Credential-stuffing detection (item 9)

Branch: `feat/credential-stuffing` (6 commits, unmerged, unpushed,
branched from `feat/anomaly-detection` rather than `main` — item 9
extends item 8's store and is not reviewable without it, so this branch
carries item 8's commits too).

Built: report-only detection of "one IP failing against many different
accounts," the gap per-account lockout structurally cannot see. Pure
threshold arithmetic in `security/stuffing.go`, the storage-reading pass
plus cooldown in `auth/stuffing.go`, one new store method
(`CountTargetsForIP` returning `store.IPTargetCounts`, memory +
postgres, **no migration** — same rows and same partial index
`CountFailuresForIP` already used), a `credential_stuffing_detected`
audit event, and `Config.CredentialStuffingThresholds`. Called from
`recordLoginFailure` (where a spray is visible at all) and from
`completePrimaryAuth` (where a spray that landed is visible). 24 new Go
tests, a 99-check smoke test at `cmd/smoketest/credential-stuffing`, and
`docs/testing/credential-stuffing.md`.

Assumptions made (spec left these open):

- **No second on/off switch.** `Config.Anomalies` turns both detectors
  on. This is the same `login_attempts` history read a second way, not a
  second tracking system, and "per-IP failure velocity but specifically
  not its breadth counterpart" is not a coherent configuration. Each
  detector still has its own threshold struct, defaulted independently,
  so setting `TargetAccounts` (or `Window`) to zero silences this one
  alone — tested explicitly, in both directions.
- **Unknown-email targets are counted as attempts, not distinct
  targets.** `store.LoginAttempt` deliberately never records which email
  was tried, so ten failures against one nonexistent address count as
  ten. `Breadth()` sums real accounts and unknown-target failures; the
  default threshold (10 targets / 1 hour) leaves headroom for the
  overcount. The alternative — storing attempted emails — would add PII
  the engine has no other use for.
- **`unknown_account_spray` is a qualifier, never a standalone bar.** A
  second independent threshold would either duplicate `account_spray` or
  leave the mixed case (a few real accounts plus many unknown) clearing
  neither. It fires only alongside `account_spray`, and only when
  unknown targets strictly outnumber real ones.
- **Ordering is the opposite of item 8's.** Breadth is measured *after*
  the triggering attempt is recorded, so the burst being judged includes
  it and the tenth distinct target trips a threshold of ten at ten. Item
  8 reads its baseline *before* recording, so an attempt never appears
  in its own history. Both are deliberate; the comments say so at each
  call site.
- **`Cooldown` (default 15m) collapses a sustained spray into one event
  per IP**, decided by a bounded 50-event newest-first `SearchByType`
  scan that fails open. Without it a spray writes one audit row per
  failed attempt. A duplicate event is the acceptable failure direction;
  a missed attack is not.

Verification: `go build ./...`, `go vet ./...` and `go test ./...` all
run clean here, and the smoke test passes all 99 checks. Postgres was
not exercised — no database in this environment, so
`CountTargetsForIP`'s `COUNT(DISTINCT user_id)` /
`COUNT(*) FILTER (WHERE user_id IS NULL)` query is reviewed-and-compiled
only; sections 1-2 of the manual test guide cover checking it against a
real one.

The `TestLogin_NonexistentUserTimingMatchesWrongPassword` flake noted in
item 8's entry recurred once here (ratio 0.29 under load, then 6 clean
isolated runs and a clean full suite). Confirmed unrelated to this item
by running the same test on `ed7de90~1` in a throwaway worktree. Still
pre-existing, still unfixed, still worth its own small branch.

Next in queue: item 10, named/fingerprinted sessions — the item where
`NEXT.md` explicitly expects a documented judgment call.

## 2026-09-04 — Named/fingerprinted sessions (item 10)

Branch: `feat/named-sessions` (7 commits, unmerged, unpushed, branched
from `feat/credential-stuffing` at `36690bf` — the tip of the chain, so
this branch carries items 8, 9 and 10).

Built: a human-readable label for each active session —
"Chrome on Windows — San Francisco, CA" instead of a UUID — for a "your
devices" settings page. `security/useragent.go` parses the device half
(`Device`, `ParseUserAgent`, the `Form*` constants), `security/
geolocation.go` defines the location half as an interface with **zero
implementations** (`IPGeolocator`, `Location`), `session/named.go`
composes them (`NamedSession`, the exported `Label`, `ListNamed`), and
the facade exposes `ListNamedSessions` plus `Config.Geolocator`. No store
change, no migration, no new query.

`NEXT.md` flagged this as the vaguest item in the backlog and asked for
the reasoning in writing, so:

- **Labels are computed on read, not stored.** The `IP` and `UserAgent`
  needed are already on `store.Session`. Storing a derived string would
  add a column, a migration and a backfill to own a value that can be
  recomputed for free — and would freeze old sessions at whatever the
  parser knew on the day they were created. As built, every session ever
  recorded gets a label the first time it's listed, and improving the
  parser improves history retroactively. The smoke test checks exactly
  this by listing the same stored session from two engines.
- **The user-agent parser ships for real, with no swap interface.**
  `NEXT.md` left this open. Parsing is pure string matching over data the
  engine already holds, so the "engine never reaches outward" rule
  doesn't apply, and an interface with no implementation would ship a
  feature that does nothing by default. A host wanting a different
  library runs it over `store.Session.UserAgent`, which stays exposed
  verbatim — so the escape hatch already exists without a second
  interface to configure.
- **Geolocation is interface-only, `Config.Geolocator`, zero shipped
  implementations** — the `BreachedPasswordChecker` rule, unchanged.
  This is the half the engine structurally cannot compute. I kept it in
  the engine rather than pushing it entirely to the host app (the
  alternative `NEXT.md` offered) because the composition is the feature:
  a label needs both halves in one string, and leaving location at the
  host layer means every host re-implements label formatting. The
  interface is one method and costs nothing to leave nil.
- **`Location` granularity is the host's choice.** `String()` joins the
  non-empty fields with ", " and does nothing else — no abbreviating,
  no expanding, no inferring a country from a region. A host filling in
  City+Region gets "San Francisco, CA"; adding Country gets
  "San Francisco, CA, US".
- **Fails open, and asks once per distinct IP per call.** A geolocator
  error is logged and treated as "location unknown"; the listing itself
  never fails, because that list is how someone revokes an attacker's
  session. The per-call cache (not per-process) avoids N lookups for a
  laptop and phone on one address without owning an invalidation story.
- **No user-editable nicknames.** "Named" here means engine-derived. A
  host that wants "Ray's work laptop" stores that itself keyed by session
  ID; adding a display-name column would be a storage feature wearing
  this item's name.
- **No version numbers in labels**, and bots/CLI clients report no OS —
  "Bingbot on Windows" would be a device claim a bot's UA can't support.

Verification: `gofmt -l .` clean, `go build ./...`, `go vet ./...` and
`go test ./...` all run clean here, and the smoke test passes all 42
checks. Nothing in this item touches storage, so there is no Postgres
path left unexercised — `ListByUser` is the only store call involved and
it predates this work. The parser is tested against authentic
User-Agent strings rather than invented ones, since the only real risk
in it is browsers impersonating each other inside the header (the CUBOT
case is why the generic bot heuristic runs after browser matching).

The `TestLogin_NonexistentUserTimingMatchesWrongPassword` flake noted in
items 8 and 9 did not recur this session. Still unfixed, still worth its
own small branch.

Next in queue: item 11, the Redis-backed rate limiter.

## 2026-09-05 — Redis-backed rate limiter (item 11)

Branch: `feat/redis-rate-limiter` (6 commits, unmerged, unpushed,
branched from `feat/named-sessions` at `345b2d7` — the tip of the chain,
so this branch carries items 8, 9, 10 and 11).

Built: `security/RedisRateLimiter`, a second real implementation of the
existing `security.RateLimiter`, so counters live in Redis instead of a
per-process Go map. `security/redisratelimiter.go` holds the type, two
constructors and the Lua; `security/errors.go` gains three sentinels;
`Config.RateLimiter` accepts an already-constructed limiter and
`engine.go` falls back to the in-process default only when it is nil.
Nothing in `auth/` changed — every call site already held the interface.

Assumptions and calls made, none of which `NEXT.md` specified:

- **`github.com/redis/go-redis/v9`**, and the injected type is that
  library's own `redis.Scripter` rather than `*redis.Client` or a bespoke
  narrow interface. Client, ClusterClient, Ring and UniversalClient all
  satisfy it, `redis.NewScript`'s EVALSHA→EVAL fallback comes along for
  free instead of being reimplemented, and a fake stays writable via
  `redis.NewCmdResult`/`redis.ErrNoScript`. This is the engine's first
  direct third-party dependency of this kind — justified on `NEXT.md`'s
  own terms: Redis is configured infrastructure, the same category as
  Postgres and `lib/pq`, not an internet service like HIBP.
- **One Lua script per `Allow`.** INCR and PEXPIRE as two round trips
  lets two replicas each arm their own window over one key, which is
  precisely the bug this item exists to fix.
- **`PEXPIRE` only when `INCR` returns 1** (or when `PTTL` reports no
  expiry, which self-heals a counter left without one). Arming it on
  every call is the more obvious idiom and is wrong: it turns a blocked
  client's own retries into a permanent block, and it would also break
  parity with the in-memory limiter's fixed window.
- **Fixed-window parity is deliberate.** Same allow/deny arithmetic as
  `InMemoryRateLimiter` (calls 1..limit pass, limit+1 denied, window
  never extended) so the two are interchangeable. A sliding window would
  be a different feature with a different cost, not an improvement
  smuggled into this one.
- **Two positional constructors** (`NewRedisRateLimiter` and
  `...WithPrefix`) over functional options, matching every other
  constructor in the repo. Default prefix `cryden:ratelimit:` so a
  counter can never collide with a host app's own keys; an empty prefix
  is legal and means raw keys.
- **Windows under 1ms are rejected, not rounded.** `PEXPIRE` cannot
  express them. This is the one place the two implementations are not
  interchangeable, and it is documented as such rather than papered over.
- **Fail-closed left as it was.** All three call sites already propagate
  a limiter error, so wiring Redis makes it a hard dependency of SignUp,
  Login and RequestMagicLink. Changing caller behaviour was out of scope
  for this item; instead the trade-off is documented, along with the
  fail-open wrapper a host can write against the interface. The error is
  wrapped, never `ErrRateLimited`, so callers can still tell "limit hit"
  from "limiter broken".
- **Exactly one key per call**, so Redis Cluster needs no special
  handling and the script never spans hash slots.
- Replaced a stale comment in `go.mod` that claimed the module proxy was
  unreachable; it is, and go-redis is now a direct require.

Verification: `gofmt -l .` clean, `go build ./...`, `go vet ./...` and
`go test ./...` all clean, `go test -race` clean, and the smoke test
passes all 58 checks over ten scenarios.

**The one real gap: no Redis server was reachable here** (no daemon,
`docker info` unavailable), so the Lua was executed only against a
stand-in that models its semantics, never by Redis itself. The Go side —
allow/deny arithmetic, the fixed window, prefixing, the EVALSHA→EVAL
fallback, fail-closed propagation through the engine — is genuinely
tested; the script's own behaviour on a real server is not. Rather than
claim otherwise, the smoke test takes `REDIS_ADDR` and runs every
scenario against a live server, namespacing and cleaning up its own
keys, and `docs/testing/redis-rate-limiter.md` opens with the two
commands that close the gap. Worth doing before this branch is merged.

Next in queue: item 12, Argon2id as an additional trusted hasher.

## 2026-09-05 — Argon2id hasher (item 12)

Branch: `feat/argon2id-hasher`, off `feat/redis-rate-limiter` at
`334c071` (so it carries items 8–12). 7 commits.

Built a second `security.Hasher` — `Argon2idHasher` writing PHC strings
(`$argon2id$v=19$m=…,t=…,p=…$salt$key`), a `MultiHasher` that dispatches
`Compare` on the stored hash's own format, `Config.Hasher`, and
upgrade-on-login in `auth/rehash.go` recording a new
`store.EventPasswordHashUpgraded` audit event.

Assumptions and decisions made without asking:

- **Format sniffing, as the spec suggested** — and worth stating why it
  is the right answer rather than merely the common one: it makes
  verification *stateless*. An algorithm column can disagree with the
  hash sitting next to it; a prefix cannot. So there is no migration, no
  backfill, and no window where some accounts can't log in.
- **`Config.Hasher security.Hasher`, already constructed**, with
  `BcryptCost` ignored when set — item 11's `Config.RateLimiter`
  precedent applied verbatim, rather than an algorithm enum plus a params
  struct. Cost parameters stay where they can be tuned to the host's
  hardware.
- **The engine wraps unconditionally in `MultiHasher`.** Dispatch is free
  (a stored hash names its own algorithm), so there is no configuration
  in which "old hashes stopped verifying" can happen. `NewMultiHasher` is
  idempotent so a host that wraps its own hasher gets no second layer.
- **`Rehasher` is an optional interface, not part of `Hasher`.** Adding a
  method to an exported v2 interface would break every host that
  implements it. A non-`Rehasher` primary simply never triggers an
  upgrade — the only safe default, since there's no way to guess what
  someone else's implementation considers out of date.
- **Upgrade-on-login is in scope.** The spec's "mid-migration user base"
  is otherwise unreachable: without it, an account that never changes its
  password never migrates. Implemented fire-and-forget — the login
  already succeeded before it runs, so a store that refuses the write
  logs an error and the login still returns tokens. `ChangePassword`
  needed nothing; it already writes a fresh hash.
- **"Out of date" means weaker, never merely different**, and excludes
  `Parallelism`: it's a hardware-shaped throughput knob, and including it
  would rewrite every stored hash the first time the service moved to a
  machine with a different core count. A stronger stored hash is left
  alone rather than walked back down.
- **Defaults are RFC 9106's second option** (64 MiB, t=3, p=4, 16-byte
  salt, 32-byte key). Zero-value `Argon2idParams{}` means defaults; one
  field set counts as a real config, same rule as `PasswordPolicy`.
- **Panic guards on the decode path.** `x/crypto/argon2` panics on
  `time < 1` or `threads < 1`, so both the constructor and the decoder
  reject those, and the decoder caps `m=` at 4 GiB — a corrupt stored
  parameter must not turn a login into a multi-terabyte allocation. The
  params segment is also round-tripped through the encoder, which rejects
  trailing junk and leading zeros that `Sscanf` would otherwise accept.
- **No new module dependency**: `golang.org/x/crypto` was already
  required by bcrypt.

One thing the smoke test found and the docs now record: a hash truncated
*inside* its base64 key is not detectably malformed — a shorter key is a
legal parameter choice, and the decoder accepts the length it finds so
that hashes written under other `KeyLength`s keep verifying. It reads as
a password mismatch instead, which is the outcome that matters.

One pre-existing flake fixed on the way past, not caused by this item:
`TestLogin_NonexistentUserTimingMatchesWrongPassword` compared a single
cost-4 bcrypt sample per path against a `ratio < 0.5` floor, which one
scheduling hiccup could breach — about one full-suite run in five once
the new packages added parallel load. It now takes the fastest of five
samples per path (noise only ever adds time, so the minimum is the best
estimate of the real work) and passes a lockout threshold high enough
that later samples still reach `hasher.Compare` instead of returning
`ErrAccountLocked`. Verified both ways: 8/8 clean with the dummy hash in
place, and still failing at ratio 0.00 with it removed, so the
regression it exists to catch is caught with a far wider margin than
before.

Verification: `gofmt -l .` clean, `go build ./...`, `go vet ./...` and
`go test ./...` all clean (three consecutive full runs), and `go run
./cmd/smoketest/argon2id-hasher` passes all 120 checks over twelve
sections. Unlike item 11 there is no external service to reach, so
nothing here is left unverified.

## 2026-09-05 — SQLite storage backend (item 13)

Branch: `feat/sqlite-store`, off `feat/argon2id-hasher` at `ca80f05`
(so it carries items 8–13). 9 commits.

Implemented all nine `store.X` interfaces plus `ai.QueryableStore`
against SQLite in a new `store/sqlite` package: ten tables in one
migration, ten store types, eleven test files (53 funcs), a 160-check
smoke test and a manual guide. Nothing outside the new directory
changed — no interface, no `store/postgres` file, no shared helper.

Assumptions and decisions made without asking:

- **SQLite, confirmed rather than assumed.** `NEXT.md` said "most likely
  candidate"; the deciding argument is that it is the only backend that
  changes *deployment shape* rather than vendor — a single file, no
  server — which is what a second backend is for. It also stresses the
  interfaces hardest, having no UUID function, no `RETURNING` on old
  versions, and foreign keys off by default.
- **The package imports no driver at all.** A host picks mattn, modernc
  or ncruces and registers it; `modernc.org/sqlite` is in `go.mod` for
  tests and the smoke test only, chosen because it is pure Go so
  `go test ./...` still works at `CGO_ENABLED=0`. Cost: forgetting the
  blank import is a runtime `unknown driver` rather than a compile error.
  Worth it — Postgres users load none of it, and the pragma DSN syntax is
  per-driver anyway, so bundling one would have implied a portability
  the DSN cannot deliver.
- **Timestamps are fixed-width TEXT, format
  `2006-01-02T15:04:05.000000000Z07:00`, always UTC, exactly 30 chars.**
  Fixed width is the entire point: it makes lexicographic order equal
  chronological order, which is what makes every `ORDER BY created_at
  DESC` and every `created_at >= ?` window correct as a string compare.
  `time.RFC3339Nano` is unusable for *writing* — it trims trailing zeros,
  producing values of varying width that sort wrongly against each other.
  Columns are declared `TEXT` and never `DATETIME`, because
  `mattn/go-sqlite3` converts declared date/time columns into `time.Time`
  and would break every scan in the package. Asserted via
  `pragma_table_info` in the smoke test so a future schema edit can't
  quietly reintroduce it.
- **`UserStore.Delete` cascades by hand, in a transaction.** SQLite
  defaults `foreign_keys` to *off*, so `ON DELETE CASCADE` is a comment
  unless the host's DSN says otherwise — and the failure is silent: a
  deleted account whose session rows survive means refresh tokens that
  keep rotating for a user who no longer exists. Correctness must not
  depend on how someone spelled a DSN. The DDL keeps its constraints
  anyway, for hosts that do set the pragma and for `sqlite3` sessions.
  `audit_events` and `login_attempts` get their `user_id` NULLed instead
  of being deleted, matching their `ON DELETE SET NULL` — the security
  record outlives the account.
- **`CheckPragmas` rather than setting pragmas ourselves.** Pragmas are
  per-connection and `*sql.DB` is a pool that opens connections whenever
  it likes, so a pragma we set on one connection says nothing about the
  next; only the DSN reaches all of them, and the store doesn't own the
  DSN. So it reports instead — both problems in one error, so one startup
  log is enough. `journal_mode` deliberately not checked: rollback
  journal is slower under concurrency, not wrong, and a host on a network
  mount can't comply.
- **The Postgres-isms, each with a real solution rather than a syntax
  swap.** `RETURNING` avoided entirely (needs 3.35, Mar 2021; Debian
  bullseye still ships 3.34.1) — `UPDATE` then `SELECT` inside one
  transaction, which is also what makes the returned number the one this
  call produced. `COUNT(*) FILTER` (3.30) became `COUNT(CASE WHEN … THEN
  1 END)`, and COUNT not SUM: over zero rows COUNT is 0 while SUM is NULL
  and won't scan into an `int`. `gen_random_uuid()` became `uuid.NewV7()`
  in Go, time-ordered to suit the created-at indexes. `JSONB` became TEXT
  holding JSON, passed as a `string` and not `[]byte` so SQLite's `json_*`
  functions can read it. `BYTEA` became BLOB. `ILIKE` became `LIKE`,
  already ASCII-case-insensitive. Upsert (`ON CONFLICT … DO UPDATE`) is
  the one that needed nothing — SQLite has had it since 3.24.
- **Store-assigned vs caller-supplied timestamps follow Postgres exactly.**
  Where Postgres has `DEFAULT now()` the store assigns and ignores the
  struct field; where Postgres binds a caller value (`ExpiresAt`,
  `LockAccount(until)`) the caller's value is honoured. Honouring a
  caller's `CreatedAt` would have made tests easier and the two backends
  divergent.
- **`mode=ro` on a second handle for `SafeQueryStore`, not `PRAGMA
  query_only`.** Same pooling argument as above: a pragma on one
  connection says nothing about the next, while a read-only *handle*
  binds every connection the pool ever makes. That handle is the actual
  boundary — a bug in `ai.validateIntent` or in the query builder still
  cannot write — and the allowlist re-check inside `RunSafeQuery` is
  defense-in-depth on top, not a substitute. The tests prove it by
  opening `mode=ro` and watching `DELETE`, `UPDATE` and `DROP TABLE` all
  fail.
- **One migration file, not the six Postgres has.** There is no deployed
  SQLite database to migrate incrementally from, so a transcribed history
  would have been fiction. `Migrate` still records what it applied, so
  future changes add numbered files normally.
- **Tests use files under `t.TempDir()`, not `:memory:`.** A bare
  in-memory database belongs to one connection, so a pool's second
  connection sees an empty schema — it fails as `no such table`,
  intermittently, under load. Files are what a host actually runs and are
  the only way WAL, `busy_timeout` and `mode=ro` mean anything. The smoke
  test's last section makes the trap deterministic by holding a
  connection out of the pool so the next query is forced onto a fresh
  one, then shows `cache=shared` fixing it.

Verification: `gofmt -l .` clean, `go build ./...`, `go vet ./...` and
`go test ./...` all clean (`store/sqlite` 53 funcs, 3.8s), and `go run
./cmd/smoketest/sqlite-store` passes all 160 checks over nine sections.
Two things caught on the way: the facade documents but does not alias
`*auth.ErrSecondFactorRequired`, and `Config` requires `EncryptionKey`
whenever `TOTP` is set — both smoke-test wiring fixes, no engine change.
No external service was needed, unlike item 11.

Next in queue: item 14, cloud logger integrations.

## 2026-09-05 — Cloud logger integrations (item 14)

Branch: `feat/cloud-loggers`, off `feat/sqlite-store` at `5862412` (so it
carries items 8–14). 11 commits.

Answered the spec's own question — interface-only or a shipped
implementation — with **interface-only, zero vendor clients**, then built
the four local pieces a host needs on this side of that call:
`ContextLogger`/`LogFunc`/`ForContext`, `LevelFilter`, `Redactor`
(masking and keyed-hashing), `MultiLogger`, plus `Level`/`ParseLevel`,
`NopLogger` and two sentinel errors. Seven new files in `logger/`, one
new method in `engine.go`, a 24-site substitution in `cryden.go`, six new
`logger` test files, two new facade tests, a 50-check smoke test and a
manual guide. No new `Config` field, no dependency change.

Assumptions and decisions made without asking:

- **No `DatadogLogger`, and the package doc says never.** The spec's test
  applies directly: a vendor integration is an outbound HTTPS call with
  an API key, batching, retry and payload rules attached, which is what
  kept `BreachedPasswordChecker` and `IPGeolocator` implementation-free.
  Stdout-as-JSON is already the integration point every shipper can tail.
  Shipping nothing at all would have been a shrug, though — the value is
  in the local half, which contains no socket.
- **The context binding happens once per facade call.** Trace IDs live
  under host-private context keys, so a hosted sink needs the context
  itself. The three ways to get it there were: add a ctx parameter to
  `Logger` (breaks every host implementation), thread ctx through the 91
  log call sites in `auth/`/`session/`/`token/` (invasive, and those
  packages have no ctx at most of them), or bind once at the only layer
  holding both. `Engine.logFor(ctx)` is the third: 24 edits in one file,
  nothing below the facade touched. `ContextLogger` is a second optional
  interface — the `MagicLinkSender`/`Rehasher` precedent — and
  `ForContext` hands a plain Logger back unchanged, which is why the
  console default keeps working and costs nothing.
- **Every wrapper implements `ContextLogger` and forwards through one
  shared `emit`.** The trap this avoids is real and quiet: a filter or
  redactor that forwarded through `Debug`/`Info`/`Warn`/`Error` would
  strip the trace ID on the way past, making "cheap" and "correlated" a
  choice a host should never have to make.
- **One `clamp`, shared by `Level.String`, `emit` and `LevelFilter`.** An
  out-of-range level must not be droppable by the filter while still
  being loggable by the sink. Unknown severities clamp rather than
  vanish — losing a record to a bad level is the worst outcome available.
- **Hashing mode is keyed HMAC-SHA256, not a bare digest.** The whole
  IPv4 space is 2^32 values, so an unkeyed hash of an address is an
  afternoon of precomputation away from being the address. Keyed and
  stable, it still answers "one IP, forty accounts", which is the shape
  credential stuffing has and the thing `[redacted]` erases. Truncated to
  64 bits: readable in a log line, collision-free at any real volume.
  An empty key is refused outright (`ErrMissingHashKey`).
- **Redaction keeps the field key and only replaces the value**, never
  mutates the caller's map (it copies when it changes something), and
  covers `fields` only — engine messages are constant strings, and
  scanning free text for personal data is a heuristic this package will
  not pretend to do reliably. `DefaultRedactedKeys()` is `ip`, `user_id`
  and `requesting_user_id`; the last was added after surveying every
  field key the engine logs, because a redactor that lets a user ID
  through on account of a key prefix is worse than none. Keys match
  case-insensitively for the same reason. It is a function, not a var, so
  the default set is not editable from anywhere.
- **No `Config.LogLevel`, `LogFormat` or `RedactFields`.** Hosts compose
  wrappers around their own sink, the same way `Config.RateLimiter` and
  `Config.Hasher` are injected already constructed. `Config.Logger` stays
  the only knob and stays optional.
- **`console.go` timestamps moved to `RFC3339Nano`.** One login emits
  several records; at second precision they all carry the same timestamp
  and nothing downstream can order them. This is the only behavioural
  change to existing output in the item, and the smoke test asserts it
  end to end by requiring distinct timestamps across one login's lines.
- **Also fixed, on its own branch: a committed 9.8 MB binary.** Item 12's
  session committed a compiled `argon2id-hasher` smoke-test binary
  (`57a5dbd`), still tracked on every branch since. `fix/committed-
  smoketest-binary` (one commit, `a59d065`, off `feat/sqlite-store`)
  untracks it and extends `.gitignore` to cover every smoke-test binary
  name. It deliberately does **not** rewrite history to drop the blob —
  that is the human's call.

Verification: `gofmt -l` clean, `go build ./...`, `go vet ./...` and `go
test ./...` all clean, and `go run ./cmd/smoketest/cloud-loggers` passes
all 50 checks over eight sections — a `ContextLogger` sink, a
context-free one, level filtering, both redaction modes, fan-out, a sink
that panics mid-login, and the stdout default. No external service
needed. Nothing surprising came up: the level filter dropping exactly the
two `info` completions while keeping the `warn` matched the survey of
what the engine actually logs (one `debug` call site in the entire
engine, `error` used only for audit-write failures).

Next in queue: item 15, extensible JWT claims.

## 2026-09-05 — Extensible JWT claims (item 15)

Branch: `feat/jwt-claims`, off `feat/cloud-loggers` at `40fa2db` (so it
carries items 8–15). 7 commits.

`Config.AccessTokenClaims` takes a `token.ClaimsProvider`
(`AccessTokenClaims(ctx, userID) (map[string]any, error)`, plus a
`ClaimsFunc` adapter) and whatever it returns is merged into every access
token; `cryden.VerifyTokenWithClaims` reads it back. New:
`token/claims.go`, `token/claims_test.go`, `claims_facade_test.go`,
`cmd/smoketest/jwt-claims/`, `docs/testing/jwt-claims.md`. Changed:
`token/jwt.go` (rewritten around `jwt.MapClaims`), `token/errors.go`,
`config.go`, `engine.go`, `cryden.go`, `auth/login.go`,
`token/jwt_test.go`. No dependency change — `golang-jwt/jwt/v5` was
already there.

Assumptions and decisions made without asking:

- **The hook, not an `extraClaims` parameter.** `NEXT.md` left the choice
  open. Decided by one fact: the host cannot supply claims on the refresh
  path at all, since `RefreshToken` takes a refresh token and nothing
  else. A parameter would need threading through six facade functions and
  would still leave refreshed tokens claimless — the worst failure mode
  available, where authorization works for fifteen minutes and then
  quietly stops.
- **Additive surface, nothing renamed.** `Issue` and `NewJWTIssuer` are
  public API in a released v2 module, so they stay and delegate:
  `Issue` → `IssueWithContext(context.Background(), …)`, `NewJWTIssuer` →
  `NewJWTIssuerWithClaims(…, nil)`. The `NewRedisRateLimiterWithPrefix`
  precedent. Exactly two call sites moved to the ctx form —
  `auth/login.go`'s `finishLogin` and `cryden.go`'s `RefreshToken`, both
  of which already held a ctx.
- **All seven registered claim names refused, all-or-nothing, before any
  merge.** `sub` is the one that matters — `Verify` reads the user ID out
  of it, so a provider able to set it could mint a token for somebody
  else. The other six are refused too so the rule does not expire the day
  the engine starts setting `aud` or `jti`. Case-sensitive, because JSON
  keys are; `SUB` is inert and passes through as ordinary host data. The
  error wraps `ErrReservedClaim` and names the offender, so a host
  debugging its own provider gets something to act on.
- **A provider error fails the token — the opposite of
  `BreachedPasswordChecker`.** That one fails open because a breach check
  is a restriction, and failing open on a restriction admits a legitimate
  user. Claims are authorization data: failing open there issues a
  credential carrying less authority than intended, into a gateway that
  may read a missing `role` as "unrestricted" rather than "denied". Added
  `ErrClaimsProvider` (a third sentinel, beyond the two originally
  planned) so a caller can recognise the class without importing the
  host's error types, wrapped alongside the host's own error with two
  `%w`s.
- **`finishLogin` now issues the access token before writing the session
  row.** Reordered because this call can genuinely fail now: a failure
  after `Create` left a session in the store for a login that returned an
  error and handed the caller no refresh token to ever use it with. A
  facade test asserts zero sessions after a failed provider.
- **On refresh the rotation cannot be undone, so a provider failure there
  costs the session.** The user's refresh token is spent and they log in
  again. Pinned by a test and documented rather than worked around —
  issuing a claimless token instead would be exactly the fail-open
  behaviour rejected above.
- **Claims are re-evaluated on every access token, not copied forward.**
  That is the role-propagation story (change a role, next refresh carries
  it) and also the cost warning: a provider call per login *and* per
  refresh, roughly every fifteen minutes per active session at the
  default TTL. Documented in `Config`'s doc comment, since it is the one
  thing a host can get badly wrong.
- **The `alg: none` defence is stronger, not weaker** — the spec's one
  hard constraint. The keyfunc's `*jwt.SigningMethodHMAC` check stays, and
  `jwt.WithValidMethods(["HS256"])` + `jwt.WithExpirationRequired()` sit
  over it. Both are kept deliberately: the keyfunc rejects a family, the
  pin rejects the members of it we do not issue, and the smoke test proves
  the difference with an HS512 token signed with the real secret, which
  the keyfunc alone would have let through.
- **`accessClaims` deleted in favour of `jwt.MapClaims`** (v5
  special-cases it in `ParseWithClaims`, so the caller's map is
  populated). The subject is now a type assertion, so an absent, empty or
  non-string `sub` is an invalid token rather than an empty user ID
  returned with a nil error. `token/jwt_test.go`'s `alg: none` test was
  updated to build `jwt.MapClaims{"sub": "attacker"}`.
- **No size cap on claims, and no `sid`.** A cap low enough to be safe
  behind every proxy would be too low to be useful; the header risk is
  documented in the testing guide instead. `sid` would be a claim the
  engine sets itself, not host data, so it is out of scope for this item.
- **README left alone.** It has not been updated since item 7 and
  mentions none of items 8–14 either; adding a section for this one alone
  would document claims while still omitting Argon2id, SQLite, the Redis
  limiter and the logger work. Worth one deliberate pass by the human,
  not seven inconsistent ones.

Verification: `gofmt -l` clean on every changed file, `go build ./...`,
`go vet ./...` and `go test ./...` all clean, and `go run
./cmd/smoketest/jwt-claims` passes all 75 checks over eight sections —
the round trip, the no-provider default (payload holds exactly
`exp,iat,sub`), refresh re-evaluation, all seven reserved names, the
fail-closed pair, unusable claims, eight forged tokens signed with the
engine's own secret, and the decoded payload printed for inspection. No
external service needed.

Next in queue: item 16, API keys / machine-to-machine auth.

## 2026-09-05 — item 16, API keys / machine-to-machine auth

Branch: `feat/api-keys` (8 commits, branched from `feat/jwt-claims` at
`8bb452b`). Built: `store.APIKeyStore` in all three backends behind
SHA-256 hashes and a unique `key_hash` index, `auth/apikeys.go`, and
four facade functions — `GenerateAPIKey` (returns `ck_<64 hex>` once),
`AuthenticateAPIKey` (→ `APIKeyIdentity`), `ListAPIKeys`,
`RevokeAPIKey`. Migrations `0007_api_keys` (Postgres) and
`0002_api_keys` (SQLite). The spec's assumption held: no M2M auth
existed anywhere in the tree, and this sits outside the second-factor
system entirely.

Assumptions and decisions, none of which the spec settled:

- **`ListAPIKeys` is a fourth function beyond the three asked for.**
  `RevokeAPIKey` takes a key ID and nothing else returns one after
  creation, so the spec's three do not compose into a usable feature.
- **Key secrets reuse the engine's refresh-token generator** rather
  than adding a `APIKeyByteLength` knob. 32 bytes by default, the
  existing 16-byte minimum still enforced; one entropy setting instead
  of two that can disagree.
- **Password lockout deliberately does not reach keys.** Otherwise
  anyone who knows a developer's email address can take down that
  account's production integrations by failing to log in five times.
  Revocation is what stops a key.
- **No rate limiting on the authenticate path.** Limiting by key needs
  the key hashed and looked up first, at which point the work is
  already done; limiting by IP would throttle the CI runner this
  exists for. Documented as the host's job at the edge.
- **Successful and unrecognised authentications record no audit row** —
  one per request would bury the table, and auditing unknown keys hands
  anyone with a wordlist a write endpoint into it. Only refusals of
  keys that really exist are recorded, with `reason`.
- **`LastUsedAt` is written at most once every five minutes per key**,
  so the hot read is not also a write. It answers "still in use", not
  "when exactly".
- **Expired keys stay listed; revoked ones do not.** An expired key is
  something its owner may want to renew, a revoked one is a decision
  already made.
- **No dedicated `store/memory/api_key_store_test.go`.** Nine of the
  ten memory stores have no test file (only `anomaly_store`, which has
  real windowing logic); this one is exercised throughout
  `auth/apikeys_test.go` and the root end-to-end test.
- **`Config.APIKeyPrefix` is validated at `New`**, not at first use —
  no whitespace and no underscore, since the underscore separates the
  prefix from the secret.

Verification: `gofmt -l` clean on every changed file, `go build ./...`,
`go vet ./...` and `go test ./... -count=1` all clean (25 new tests),
and `go run ./cmd/smoketest/api-keys` passes all 96 checks over ten
sections — the round trip, the unconfigured path, listing, revocation,
expiry, nine malformed keys, refused arguments, a locked-out account
whose key keeps working, the audit trail, and the stored hash printed
for inspection. No external service needed.

Next in queue: item 17, webhooks.

## 2026-09-05 — item 17, webhooks

Branch: `feat/webhooks` (7 commits, branched from `feat/api-keys` at
`f11e40e`). Built: `notify.WebhookSender` —
`SendWebhook(ctx, notify.WebhookEvent) error`, one method, zero shipped
implementations — plus `Config.Webhooks`, `Config.WebhookEvents`,
`cryden.DefaultWebhookEvents()`, and the unexported `webhookRecorder` in
`webhooks.go` that does the wiring. No store change, no migration, no
new dependency.

Assumptions and decisions, all of them mine to make:

- **A decorator over `store.AuditStore`, not a sender parameter on the
  33 `audit.Record` call sites.** `New` wraps `Config.Audit` when
  `Webhooks` is set, `Record` writes the row then dispatches. The spec
  said "wire it in wherever `audit.Record` is already called" and "don't
  build a second parallel event bus"; wrapping the interface satisfies
  both without touching `auth/` at all, and makes "audited but never
  delivered" structurally impossible for event types added later.
- **The default subset is sixteen events**, the ones bounded by human
  action, excluding `login_success`, `token_rotated` and `login_failed`.
  A thousand logged-in users at the default 15-minute `AccessTokenTTL`
  is 4,000 `token_rotated` deliveries an hour, and `login_failed` volume
  is chosen by an attacker. `DefaultWebhookEvents()` returns a fresh
  slice so appending one back is safe and documented.
- **No "all" switch.** It would silently start delivering event types
  added to the engine after the host wrote its sender.
- **Delivery is synchronous, on the request path.** The interface's doc
  comment says to enqueue rather than make the HTTP call there. No
  engine-side goroutine: unbounded is a leak under load, bounded is a
  queue the host would rather own.
- **A send error is logged and swallowed; a panic is not recovered.**
  Following `logger/multi.go`'s own written rule — recovery exists there
  only because a second sink can still preserve the record. Confirmed by
  grep that it is the only `recover()` in non-test code.
- **The audit row is written first, and a failed write still delivers.**
  The row is the system of record; the event happened either way.
- **`WebhookEvent.ID` is a delivery/idempotency key, not the audit row's
  ID.** No backend reports its row ID back — Postgres uses
  `gen_random_uuid()`, memory ignores a caller-supplied ID — so claiming
  it was the row's would be a lie the host might join on.
- **`Metadata` is copied before delivery.** The in-memory store holds
  the map by reference, so a sender editing it could rewrite audit
  history. Pinned with a test.
- **Two sentinels, `ErrMissingWebhookSender` and
  `ErrInvalidWebhookEvent`.** A misspelled-but-non-empty event type
  builds and is silently never delivered: there is no canonical list of
  event types to validate against, and inventing one would put the
  constants in two places that must agree forever.
- **`recovery_codes_generated` is in the default set but not
  demonstrated in the smoke test** — generating codes requires a second
  factor already enrolled, a TOTP dance the webhook test has no reason
  to perform. Five other default-set events are demonstrated through
  real facade calls instead.
- Corrected a stale "35 call sites" to 33 in `webhooks.go` and the guide
  after counting with grep.

Verification: `gofmt -l` clean on every changed file, `go build ./...`,
`go vet ./...` and `go test ./... -count=1` all clean (17 new tests), and
`go run ./cmd/smoketest/webhooks` passes all 75 checks over ten sections
— the round trip, the unconfigured path, seven default-set deliveries
from real operations, five logins and five refreshes delivering nothing,
an explicit subset, a sender that errors and one that panics, the audit
log read back, distinct delivery IDs and the caller's trace ID, both
refused configurations, and the printed payloads. No external service
needed, no HTTP call made.

Next in queue: item 18, custom email templates — which the spec itself
flags as possibly needing no engine change at all.

## 2026-09-05 — item 18, custom email templates

Branch: `feat/custom-email-templates` (4 commits, branched from
`feat/webhooks` at `6f84095`). **Built no engine code, on purpose.** The
item said to check `notify.EmailSender`/`notify.MagicLinkSender` first
because there was a real chance nothing was needed. Nothing is: the host
app already owns every byte of every email.

What the check actually found:

- **Two interfaces, two methods, two call sites in the entire tree.**
  `SendVerification` at `auth/email.go:70` (email change) and
  `SendMagicLink` at `auth/magiclink.go:88` (passwordless login). Both
  pass `(ctx, to, rawToken)` and nothing else — no subject, no body, no
  HTML, no from-address, no URL. Both doc comments already said the host
  owns the template and the URL; that is accurate, not aspirational.
- **`Config` has exactly two email-shaped fields**, and both are those
  interfaces. There is no template knob to add an override to.
- **The ambiguity the code worried about does not exist.**
  `magic_link_sender.go`'s comment justifies being a separate interface
  partly because "`EmailSender.SendVerification` has no way to signal
  which one it's sending" — with one call site each, neither
  implementation ever has to guess.
- **No missing third template.** There is no signup verification flow
  (`store.PurposeEmailVerify` has no producer outside a store smoke
  test) and no password-reset flow at all (`ChangePassword` requires the
  current password), so nothing else in the engine wants to send mail.

Decisions, since "mark it done-as-a-non-issue" still leaves what to
produce:

- **Wrote the two required artifacts anyway.** `CLAUDE.md` says every
  item gets a `docs/testing/<item>.md` and a runnable smoke test, and
  they are worth more here than usual: they turn "no engine change
  needed" from a claim in this file into something executable. The guide
  answers the question behind the item — how a host controls what those
  emails say — rather than documenting a feature that does not exist.
- **Added `custom_email_templates_test.go`** (three tests) so the
  verdict is pinned in `go test ./...`: both interfaces take only
  `(context.Context, string, string) error`, `Config`'s only
  email-shaped fields are the two senders, and a link the host composed
  on its own domain confirms an email change. A `Config.EmailSubject`
  added in a later session fails the suite instead of quietly making the
  guide wrong. Not speculative — no new API, no new behaviour.
- **Did not export the two TTLs.** This is the one real gap:
  `changeEmailTokenTTL` (1 hour) and `magicLinkTTL` (15 minutes) are
  unexported and not handed to the sender, so a template saying "expires
  in 1 hour" hardcodes a number that could drift. Exporting
  `cryden.EmailChangeTokenTTL`/`cryden.MagicLinkTokenTTL` would fix it in
  about four lines, but it is a permanent public-API commitment and the
  item explicitly said not to build something speculative to have built
  something. Recorded in the guide's "Known limits" as a queueable item
  instead, and the smoke test guards against the drift by reading the
  real `ExpiresAt` back out of the host's own `VerificationStore` and
  comparing it to the strings the templates hardcode. Adding a parameter
  to either send method was never an option — it breaks every existing
  host implementation at compile time, which is precisely why
  `MagicLinkSender` exists as its own interface.
- **The branch is named `feat/` and contains no feature.** `CLAUDE.md`
  offers `feat/` or `fix/` and neither fits a non-issue; kept the
  convention rather than inventing a prefix, and said so in
  `CURRENT-STATE.md` so nobody reads the name as a claim.

Verification: `gofmt -l` clean on both new files, `go build ./...`,
`go vet ./...` and `go test ./... -count=1` all clean (3 new tests), and
`go run ./cmd/smoketest/custom-email-templates` passes all 54 checks over
ten sections — including a host-composed URL round-tripping through
`ConfirmEmailChange`, a German template chosen from the recipient, a
provider failure leaving the address unchanged, an unknown address
sending nothing, and a reflection check that `Config` has no template
knob. No external service, no mail provider contacted.

Tier 3 is now complete (7 of 7). Next in queue: item 19, the weekly
digest — the first of Tier 4, where everything is read-only by
non-negotiable rule.

## 2026-09-06 — item 19, weekly digest

Branch: `feat/weekly-digest` (7 commits, branched from
`feat/custom-email-templates` at `4058460`). Built:
`cryden.WeeklyDigest(ctx, e)` and `cryden.DigestSince(ctx, e, since)`,
returning the audit history of a window as plain text; the new read-only
`admin` package behind them; and `store.AuditStore.CountByType` on all
three backends. No config field, no migration, no new dependency.

Assumptions and decisions, all of them mine to make:

- **Added `CountByType` to `store.AuditStore` rather than an optional
  side interface.** The house pattern for extending a frozen *behaviour*
  interface is an optional side interface (`Rehasher`, `ContextLogger`),
  but `webhookRecorder` **embeds** `store.AuditStore`, so a new interface
  method forwards through the decorator for free while an optional
  interface would be invisible behind it — the digest would have been
  empty for exactly the hosts that configured webhooks. Item 9 already
  set the precedent of extending a *store* interface in place
  (`AnomalyStore.CountTargetsForIP`). This is a compile-time break for a
  host with its own `AuditStore`, which is the right failure: a silently
  missing count reads as a calm week. There is a test for the decorated
  path specifically.
- **Counting in the store, not in Go.** The alternative was 31
  `SearchByType` sweeps filtered by timestamp, which moves up to
  `31 × limit` rows over the network to produce numbers, and can still
  only report "at least N" for the very figures a human opens a digest
  to read. One `GROUP BY type` per week is strictly cheaper than the
  status quo, so **no index and no migration were added** — Postgres
  scans, the same trade the schema already documents for `SearchByType`.
- **A new `admin` package rather than `ai`.** Item 19 involves no model:
  `ai`'s whole subject is validating untrusted model output and it
  deliberately imports no domain types. `admin.AuditReader` — the
  interface a report is handed, with `CountByType` and `SearchByType` and
  no `Record` — makes Tier 4's read-only rule a compile error instead of
  a convention, and items 20 and 21 belong in the same package without a
  rename later.
- **The window always ends now.** `DigestSince` takes a start only. The
  detail lines come from `SearchByType`, which returns the newest events
  of a type with no window of its own, so a digest ending last Tuesday
  would count correctly and come back with no detail at all. Better to
  have no end bound than one whose highlights silently empty out. A
  `since` in the future is an empty window, not an error.
- **Detail for four event types, capped at ten.** Only the
  `Needs attention` group (`account_locked`, `token_reuse_detected`,
  `anomaly_detected`, `credential_stuffing_detected` — the same four item
  17 grouped as "something is wrong") gets individual events printed;
  everything else is counted. The cap bounds what the report prints,
  never what it knows, and the text says "the 10 most recent of 12 shown"
  against the exact count. Listing 4,210 successful sign-ins would bury
  the one lockout that mattered.
- **All 31 event types are classified into five printed sections, and
  the table is not authoritative.** Anything absent — a host's own event
  type, or one the engine gains later — is counted under
  `Other events (types this engine does not define)`. A stale table
  degrades a digest; it never hides anything from it. `digestSections`
  is also what `digestAttentionTypes()` is derived from, so the queries
  that fetch detail cannot drift from the section that prints it.
- **Text, not a struct, on the facade.** The spec said "returns text.
  Nothing else", so `WeeklyDigest` returns a `string` and no type alias
  was exported. `admin.BuildDigest` and `admin.Digest` are there for a
  host that wants the numbers, without the root package committing to
  their shape.

Verification: `gofmt -l` clean on every changed file, `go build ./...`,
`go vet ./...` and `go test ./... -count=1` all clean — 46 new tests
(`admin/digest_test.go`, `digest_facade_test.go`, and the `CountByType`
suites for all three stores; the Postgres ones skip without
`DATABASE_URL`) — and `go run ./cmd/smoketest/weekly-digest` passes all 49
checks over nine sections, including a store whose reads fail being an
error rather than a report that reads like a quiet week, and no password,
hash, JWT secret or email address appearing in text meant to be mailed
around.

Next in queue: item 20, the support-ticket assistant — read-only
diagnosis of why one user cannot sign in, same `admin` package, same
non-negotiable read-only rule.
