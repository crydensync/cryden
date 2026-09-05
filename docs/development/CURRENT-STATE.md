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


## Tier 3 — Infrastructure & Extensibility: DONE (7 of 7)

Tier 4 is next. See `NEXT.md`.

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

### Item 14 — cloud logger integrations: DONE, branch `feat/cloud-loggers`

**Interface-only, zero vendor implementations** — the answer the spec
pointed at, confirmed rather than assumed. Every hosted log vendor is an
outbound HTTPS call carrying an API key with its own batching, retry and
payload rules, which is the same test that kept `BreachedPasswordChecker`
and `IPGeolocator` implementation-free; and stdout-as-JSON is already the
universal integration point, since any shipper can tail it. There is no
`logger.DatadogLogger` and the package doc says there never will be.

Shipping *nothing* would have been a shrug, though: a host pointing a
shipper at cryden hits four gaps immediately, and all four are pure local
code with no socket in them. So `logger/` gains seven files —
`context.go` (`ContextLogger`, `LogFunc`, `ForContext`), `level.go`
(`Level`, `ParseLevel`, `clamp`), `filter.go` (`LevelFilter`),
`redact.go` (`Redactor`, masking and keyed-hashing modes,
`DefaultRedactedKeys`), `multi.go` (`MultiLogger`), `nop.go`
(`NopLogger`), `errors.go` (`ErrUnknownLevel`, `ErrMissingHashKey`) —
plus a rewritten package doc and one change to `console.go`.

The engine change is deliberately small: `Engine.logFor(ctx)` in
`engine.go` and an `e.log` → `e.logFor(ctx)` substitution at 24 call
sites in `cryden.go`. That is the whole cost of trace correlation.
`Logger` itself is **unchanged and frozen** — adding a ctx parameter
would break every host implementation in existence, so `ContextLogger` is
a separate optional interface, the `MagicLinkSender`/`Rehasher`
precedent, and `ForContext` returns a plain Logger untouched. `auth/`,
`session/`, `token/` and every store are untouched, and there is **no new
`Config` field** — not even `LogLevel`: hosts compose wrappers around
their own sink, the way `RateLimiter` and `Hasher` are injected already
built. `go.mod` is unchanged.

Decisions worth not re-deriving (full reasoning in `PROGRESS.md`): the
ctx binding happens **once per facade call** rather than being threaded
through 91 log call sites in `auth/`; **every wrapper implements
`ContextLogger`** and forwards through one shared `emit`, so filtering or
redacting can never silently strip the trace ID a hosted sink was bought
for; one `clamp` shared by `Level.String`, `emit` and `LevelFilter`, so
an out-of-range level cannot be dropped by the filter and kept by the
sink; redaction is **keyed HMAC-SHA256** in hashing mode, because the
IPv4 space is 2^32 values and an unkeyed digest of an address is a lookup
table away from the address; the field **key stays present** and only the
value is replaced, so a vendor's index does not change shape; and
`console.go`'s timestamp moved `RFC3339` → **`RFC3339Nano`**, since at
second precision one login's records share a timestamp and nothing
downstream can order them.

Tests: six `_test.go` files under `logger/` (level, context, filter,
multi, redact, console — plus shared fakes in `helpers_test.go`) and two
facade tests in `new_facade_test.go` proving a real `SignUp` hands the
call context to a `ContextLogger` and still logs to a context-free one.
Smoke test: `cmd/smoketest/cloud-loggers` (50 checks over eight
sections), including a sink that panics mid-login and the stdout default.
Manual guide: `docs/testing/cloud-loggers.md`. `gofmt -l`, `go build
./...`, `go vet ./...` and `go test ./...` all clean here; no external
service needed.

### Item 15 — extensible JWT claims: DONE, branch `feat/jwt-claims`

`Config.AccessTokenClaims` takes a `token.ClaimsProvider` —
`AccessTokenClaims(ctx, userID) (map[string]any, error)` — and whatever it
returns is merged into every access token the engine issues. Read back
with `cryden.VerifyTokenWithClaims`, which is `VerifyToken` plus the
host's claims with the registered ones stripped out.

`NEXT.md` offered two shapes and the **hook won on one fact: the host
cannot supply claims on the refresh path.** `RefreshToken` takes a
refresh token and nothing else, so an `extraClaims` parameter would have
to be threaded through six facade functions and would *still* leave
refreshed tokens claimless — tokens that work for fifteen minutes and
then quietly stop carrying authorization. Injected once, it covers both
paths by construction.

Nothing existing broke: `Issue`, `Verify` and `NewJWTIssuer` keep their
signatures (`Issue` now wraps `IssueWithContext(context.Background(), …)`,
`NewJWTIssuer` wraps `NewJWTIssuerWithClaims(…, nil)` — the
`NewRedisRateLimiterWithPrefix` precedent), and exactly two call sites
moved to the ctx form: `auth/login.go`'s `finishLogin` and `cryden.go`'s
`RefreshToken`, both of which already held a ctx. A nil provider is
byte-for-byte today's behaviour. New files: `token/claims.go`,
`token/claims_test.go`, `claims_facade_test.go`,
`cmd/smoketest/jwt-claims/`, `docs/testing/jwt-claims.md`. `go.mod`
unchanged.

The security core, and the reason this item needed care: **all seven RFC
7519 §4.1 registered names are refused, all-or-nothing, before anything
is merged.** `sub` is why — `Verify` reads the user ID out of it, so a
provider able to write it could mint a token authenticating as somebody
else. The other six are refused too, so the rule does not need revisiting
the day the engine starts setting `aud` or `jti`. Matching is
case-sensitive (JSON keys are; `SUB` is inert and passes through).

The `alg: none` defence is **stronger, not weaker**, as the spec
required: the keyfunc's `*jwt.SigningMethodHMAC` check stays, and
`jwt.WithValidMethods(["HS256"])` plus `jwt.WithExpirationRequired()` sit
over it. `accessClaims` is gone in favour of `jwt.MapClaims`, so the
subject is now a type assertion — an absent, empty or non-string `sub` is
an invalid token rather than an empty user ID.

Decisions worth not re-deriving (reasoning in `PROGRESS.md`): a provider
error **fails the token**, deliberately the opposite of
`BreachedPasswordChecker`'s fail-open, because a missing claim is an
absence a gateway may read as permission; `finishLogin` therefore now
issues the access token **before** writing the session row, so a login
that fails there leaves nothing behind; on refresh the rotation cannot be
undone, so a provider failure there costs the session and the user logs
in again (pinned by a test, documented, not papered over); claims are
re-evaluated on **every** access token, which is the role-propagation
story and also a provider call every ~15 minutes per active session.

Tests: 18 in `token/claims_test.go` (every reserved name, empty name,
unmarshalable value, wrapped provider error, no-exp and HS512 forgeries,
non-string subject), six in `claims_facade_test.go` (claims in a real
login, re-evaluated on refresh, nil without a provider, and the two
fail-closed consequences). Smoke test: `cmd/smoketest/jwt-claims` (75
checks over eight sections, including eight forged tokens signed with the
engine's own secret). Manual guide: `docs/testing/jwt-claims.md`.
`gofmt -l`, `go build ./...`, `go vet ./...` and `go test ./...` all clean
here.

### Item 16 — API keys / machine-to-machine auth: DONE, branch `feat/api-keys`

A credential for a caller with no human behind it. `Config.APIKeys`
takes a `store.APIKeyStore`; `cryden.GenerateAPIKey` mints
`ck_<64 hex>` and returns the raw string exactly once;
`cryden.AuthenticateAPIKey` resolves a presented key to an
`APIKeyIdentity` (user, key ID, name, scopes); `ListAPIKeys` and
`RevokeAPIKey` are the management half.

The spec's assumption checked out — nothing M2M existed anywhere in the
tree — and this deliberately sits **outside the second-factor system**:
no `Login`, no `*ErrSecondFactorRequired`, nothing that would prompt a
pipeline for a code it cannot produce.

`ListAPIKeys` is beyond the spec's three functions, and had to be.
`RevokeAPIKey` takes a key ID, so without a way to obtain one after
creation the three do not compose into a usable feature.

**Storage.** `store.APIKeyStore` is `Create`, `GetByKeyHash`,
`ListByUser`, `Revoke`, `TouchLastUsed`, implemented in all three
backends. `key_hash` is SHA-256 via `token.HashToken` and uniquely
indexed — the hot read is one index hit — with a partial index on
`(user_id) WHERE revoked_at IS NULL` for the listing. bcrypt was
explicitly not used: 32 bytes of `crypto/rand` has no dictionary to
slow anyone down through, and the cost would be paid on every machine
request rather than once per login. Migrations `0007_api_keys`
(Postgres) and `0002_api_keys` (SQLite, the second one that package has
ever had — `TestMigrate_IsIdempotent` counted migrations by hardcoding
1 and now derives it). Postgres cascades on user deletion; SQLite's
hand-written cascade in `UserStore.Delete` gained the row.

**Deliberate refusals.** Password lockout does not reach keys — anyone
who knows a developer's email could otherwise take down that account's
production integrations by failing to log in five times. There is no
rate limiting on the authenticate path: limiting by key needs the key
hashed and looked up first, at which point the work is done, and
limiting by IP would throttle the CI runner this exists for. Scopes are
opaque host strings; `HasScope` is exact equality with no hierarchy and
no wildcards, and the engine never interprets them.

**The audit log records three things and skips two.**
`api_key_created`, `api_key_revoked` and `api_key_rejected` (with
`reason` = `revoked` or `expired`) are recorded. A *successful*
authentication is not — it happens on every request. An *unrecognised*
key is not either: that is unauthenticated internet traffic, and
auditing it hands anyone with a wordlist a write endpoint into the
audit table. A key that exists but is refused is the case only a
former holder of a real credential can trigger, which is why it is the
one that lands.

Every failure on the read path is one error, `auth.ErrInvalidAPIKey` —
unknown, revoked, expired, empty, malformed — so a caller holding
stolen keys cannot sort them into live and dead. `RevokeAPIKey` is the
same silence via `auth.ErrAPIKeyNotFound` for nonexistent,
already-revoked and somebody else's.

New files: `auth/apikeys.go`, `auth/apikeys_test.go`, the three
`api_key_store.go` implementations, `store/sqlite/api_key_store_test.go`,
four migration files, `cmd/smoketest/api-keys/`, `docs/testing/api-keys.md`.
Touched: `store/interfaces.go`, `config.go`, `errors.go`, `engine.go`,
`cryden.go`, plus SQLite's `sqlite.go`/`user_store.go` and three test
files. No new dependency. `Config.APIKeyPrefix` defaults to `"ck"` and
is validated at `New` — no whitespace, no underscore, since the
underscore is the separator.

Tests: 13 in `auth/apikeys_test.go`, 7 in
`store/sqlite/api_key_store_test.go`, 5 across `config_test.go` and
`new_facade_test.go` including a full facade end-to-end. Smoke test:
`cmd/smoketest/api-keys` (96 checks over ten sections, including nine
malformed keys, a locked-out account whose key keeps working, and five
successes plus five unknown keys recording nothing). Manual guide:
`docs/testing/api-keys.md`. `gofmt -l`, `go build ./...`, `go vet ./...`
and `go test ./...` all clean here.

### Item 17 — webhooks: DONE, branch `feat/webhooks`

The engine tells the host app what happened instead of waiting to be
asked. `Config.Webhooks` takes a `notify.WebhookSender` —
`SendWebhook(ctx, notify.WebhookEvent) error`, one method, **zero
shipped implementations**, the same shape as `EmailSender` and
`IPGeolocator`. `Config.WebhookEvents` selects which events reach it and
defaults to `cryden.DefaultWebhookEvents()`.

Wired as a **decorator over `store.AuditStore`** (`webhookRecorder` in
`webhooks.go`), not as a parameter on the 33 `audit.Record` call sites
and not as a second event bus. `New` wraps `Config.Audit` when
`Webhooks` is set; `Record` writes the row and then dispatches, so every
existing call site notifies without a line changing and nothing in
`auth/` knows the type exists. Reads pass straight through to the
wrapped store.

`DefaultWebhookEvents()` is sixteen events, the ones bounded by human
action, and deliberately excludes `login_success`, `token_rotated` and
`login_failed` — a thousand logged-in users at the default 15-minute
`AccessTokenTTL` is 4,000 `token_rotated` deliveries an hour, and
`login_failed` volume is chosen by whoever is attacking you. It returns
a fresh slice, so `append(cryden.DefaultWebhookEvents(), ...)` is the
documented way to add one back. There is deliberately **no "all"**
switch: it would silently start delivering event types added after the
host wrote its sender.

Delivery is synchronous, on the request path, immediately after the
audit write — so the doc comment on the interface says to enqueue rather
than make the HTTP call there. A send error is logged at Error level and
never fails the operation; a failed audit write still delivers; a
**panic is not recovered** and takes the request, following
`logger/multi.go`'s own stated rule that recovery exists only where a
second sink can preserve the record. `Metadata` is copied before
delivery so a sender cannot rewrite audit history, and `WebhookEvent.ID`
is a delivery/idempotency key, explicitly not the audit row's ID — no
backend reports that back.

Two new sentinels: `ErrMissingWebhookSender` (events set, no sender) and
`ErrInvalidWebhookEvent` (an empty type). A non-empty but misspelled
event type builds and is never delivered; there is no canonical list to
validate against and inventing one would duplicate the constants.

No store change, **no migration**, no new dependency, no external
service. Tests: 17 in `webhooks_test.go`. Smoke test:
`cmd/smoketest/webhooks` (75 checks over ten sections, including five
logins and five refreshes delivering nothing, a sender that errors, and
a sender that panics). Manual guide: `docs/testing/webhooks.md`.
`gofmt -l`, `go build ./...`, `go vet ./...` and `go test ./...` all
clean here.

### Item 18 — custom email templates: DONE (no engine change), branch `feat/custom-email-templates`

**Nothing was built, and that is the finding.** The queue entry said to
check `EmailSender`/`MagicLinkSender` first because there was "a real
chance this needs no engine change at all." There is nothing to build.
Checked and confirmed:

- Two interfaces, two methods, **two call sites in the whole tree**:
  `SendVerification` at `auth/email.go:70` (email change) and
  `SendMagicLink` at `auth/magiclink.go:88` (passwordless login). Each
  interface has exactly one purpose, so the "which email am I sending?"
  ambiguity `notify/magic_link_sender.go`'s doc comment worried about
  does not exist in practice.
- Both methods pass `(ctx, to, rawToken)`. The engine composes no
  subject, no body, no HTML, no plain-text part, no from-address and no
  URL — it does not know the host's domain or routing, as both doc
  comments already say.
- `Config` has exactly two email-shaped fields and both are those
  interfaces. There is no template, subject or from-address knob to
  override.
- No third or fourth template is missing either: there is no signup
  verification flow (`store.PurposeEmailVerify` has no producer outside
  a store smoke test) and no password-reset flow at all
  (`ChangePassword` requires the current password), so nothing else in
  the engine wants to send mail.

Built instead of a feature: `docs/testing/custom-email-templates.md`
answering the question behind the item (how a host controls what those
emails say, in full), `cmd/smoketest/custom-email-templates` (54 checks
over ten sections — a real host mailer with `html/template` bodies, two
languages and two providers, whose own composed URL round-trips back
into `ConfirmEmailChange` and `CompleteMagicLink`), and
`custom_email_templates_test.go`, three tests that pin the verdict by
reflection so a `Config.EmailSubject` added later fails `go test ./...`
rather than quietly making the guide wrong.

One real gap recorded rather than filled: both TTLs
(`changeEmailTokenTTL` 1 hour, `magicLinkTTL` 15 minutes) are unexported
and not passed to the sender, so a template that says "expires in 1
hour" hardcodes a number that could drift. Exporting two constants would
fix it; adding a parameter to either send method would break every
existing host implementation at compile time, which is why
`MagicLinkSender` was a new interface rather than a second method on
`EmailSender`. Queue it as its own item if the project owner wants it —
it is not done here, on the item's own "don't build something
speculative to have built something" instruction.

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

- `feat/cloud-loggers` — item 14, complete, 11 commits, branched from
  `feat/sqlite-store` at `5862412`, the tip of the chain, so this branch
  carries items 8 through 14. Unlike item 13 it **does** touch engine
  files — one method in `engine.go` and a 24-site substitution in
  `cryden.go` — so the same by-hand adjacency as items 10-12 applies if
  it is lifted onto `main` alone. It adds **no dependency** and needs no
  external service. Unmerged and unpushed.
- `feat/jwt-claims` — item 15, complete, 7 commits, branched from
  `feat/cloud-loggers` at `40fa2db`, the tip of the chain, so this branch
  carries items 8 through 15. Touches engine files (`config.go`,
  `engine.go`, `cryden.go`, `auth/login.go`) as well as `token/`, so the
  same by-hand adjacency as items 10-12 and 14 applies if it is lifted
  onto `main` alone. It adds **no dependency** — `golang-jwt/jwt/v5` was
  already there — and needs no external service. Unmerged and unpushed.
- `feat/api-keys` — item 16, complete, 8 commits, branched from
  `feat/jwt-claims` at `8bb452b`, the tip of the chain, so this branch
  carries items 8 through 16. Touches engine files (`config.go`,
  `errors.go`, `engine.go`, `cryden.go`) and `store/interfaces.go` as
  well as all three store backends, so the same by-hand adjacency as
  items 10-12, 14 and 15 applies if it is lifted onto `main` alone. It
  adds **no dependency** and needs no external service, but it does add
  **two migrations** that have to run before the feature works:
  `store/postgres/migrations/0007_api_keys.up.sql` and
  `store/sqlite/migrations/0002_api_keys.up.sql`. Unmerged and unpushed.
- `feat/webhooks` — item 17, complete, 7 commits, branched from
  `feat/api-keys` at `f11e40e`, the tip of the chain, so this branch
  carries items 8 through 17. Touches engine files only (`config.go`,
  `errors.go`, `engine.go`, the new `webhooks.go`) plus the new
  `notify/webhook_sender.go`, so the same by-hand adjacency as items
  10-12, 14, 15 and 16 applies if it is lifted onto `main` alone. It
  adds **no dependency**, **no migration** and no store change at all —
  it delivers events the audit table already recorded. Unmerged and
  unpushed.
- `feat/custom-email-templates` — item 18, complete, 4 commits,
  branched from `feat/webhooks` at `6f84095`, the tip of the chain, so
  this branch carries items 8 through 18. **Contains no engine change at
  all** — the `feat/` prefix is the naming convention, not a claim. Adds
  one root test file, one smoke test and one guide, touching no existing
  Go file, so unlike every branch before it this one lifts onto `main`
  with nothing to reconcile. No dependency, no migration. Unmerged and
  unpushed.
- `fix/committed-smoketest-binary` — not a queue item. A pre-existing
  bug found while working on item 14: a 9.8 MB compiled `argon2id-hasher`
  binary was committed to the repo by item 12's session (`57a5dbd`) and
  is still tracked on every branch from there on. One commit
  (`a59d065`), branched from `feat/sqlite-store`, untracking the file and
  extending `.gitignore` to cover every smoke-test binary name.
  It does not remove the blob from history — that needs a rewrite, which
  is the human's call, not something a session should do unasked.
  Unmerged and unpushed.

Nothing else in flight. Each new session picks the top item off
`NEXT.md`, creates its own branch, and this section should be updated to
reflect that branch's existence and status before the session ends. If you start a session and this section already
lists an in-progress branch, that means a previous session didn't
finish cleanly — check that branch's own commits before assuming
anything about its state, and update this file to match reality once
you've looked.
