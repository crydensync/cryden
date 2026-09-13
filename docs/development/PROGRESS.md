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
