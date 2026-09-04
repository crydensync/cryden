# cryden — architecture review (read sections as needed, not cover to cover)

This file exists so you never have to rediscover these conventions by
reading the source tree. If you find yourself about to grep the whole
repo "to understand how X works," check here first — it's probably
already answered.

## What this project is

`cryden` (`github.com/crydensync/cryden/v2`) is an embeddable,
framework-agnostic Go authentication engine. No HTTP, no hardcoded
storage backend, zero telemetry — it never leaves the consuming app's
infrastructure on its own initiative, including logs and audit data.
The root `cryden` package is the only public import; `auth`, `token`,
`security`, `store`, `session`, `logger` are internal implementation
detail (the root package's own doc comment says this explicitly).

## Package layout

- `cryden.go`, `config.go`, `engine.go`, `errors.go` — the public
  facade (root package). `Config` wires an `Engine` via `New(cfg)`.
  Every public function takes `(ctx, *Engine, ...)`.
- `auth/` — all business logic. Internal. This is where feature work
  actually happens.
- `security/` — pluggable security primitives. Interfaces + one
  production implementation each (`Hasher`→bcrypt, `TOTPGenerator`→
  pquerna/otp, `WebAuthnProvider`→go-webauthn, `Encryptor`→AES-256-GCM)
  — except integrations requiring an outbound network call
  (`BreachedPasswordChecker`), which ship **zero** implementations,
  same reasoning as `notify/`.
- `store/` — `interfaces.go` defines every storage contract + shared
  data types + `AuditEventType` constants. `store/memory/` = test-only
  implementations. `store/postgres/` = production, plus
  `store/postgres/migrations/*.sql` (numbered sequentially — check the
  highest existing number before adding one; currently `0005`).
- `token/` — JWT issuance (`JWTIssuer`), refresh token generation
  (`TokenGenerator`), the second-factor pending token
  (`MFAPendingIssuer`).
- `notify/` — external delivery interfaces (`EmailSender`,
  `MagicLinkSender`). Zero implementations, by design — host app
  supplies one.
- `session/` — session listing/revocation helpers.
- `logger/` — `Logger` interface, one console-JSON implementation.
- `cmd/smoketest/<feature>/main.go` — one per feature, in-memory,
  runnable, no external dependencies.
- `docs/testing/<feature>.md` — one per feature, manual verification
  steps.

## Core design rules (apply these to every new feature)

**Interface-first, one production implementation per interface**,
UNLESS the concern requires an outbound network call the engine
shouldn't make on its own initiative — those get an interface with
**zero** shipped implementations (`EmailSender`, `MagicLinkSender`,
`BreachedPasswordChecker` are the existing examples). When in doubt
which bucket a new integration falls into, ask: "does using this
feature necessarily mean cryden talks to some external service over
the network?" If yes → zero-implementation interface, host supplies
one. If it's local computation/crypto only → ship one real
implementation using a well-vetted library, same as TOTP/WebAuthn.

**Config fields for optional features are nil-safe.** Unset → the
facade function returns a clear `cryden.ErrXNotConfigured`, never a
panic. The one deliberate exception: `Config.PasswordPolicy` has no
"off" state — leaving it as the literal zero value
(`security.PasswordPolicy{}`, compared as a **whole struct**, not by
checking one field) applies `security.DefaultPasswordPolicy`
automatically. Password strength isn't opt-in the way 2FA methods are.

**Fail loudly, never silently insecure.** Security-critical
misconfiguration (missing JWT secret, missing required store) is a
hard error from `New()`, not a runtime surprise.

**Storage pattern for a new pluggable feature:**
1. Type + interface in `store/interfaces.go`.
2. `store/memory/<name>_store.go` — test implementation.
3. `store/postgres/<name>_store.go` — production implementation. If
   storing a rich/evolving struct (e.g. a third-party library's own
   type), store it as a JSON blob column rather than decomposing every
   field — see `webauthn_credentials.credential_data` for the pattern.
   **Passing a Go `[]byte` to a `jsonb` column via `lib/pq` sends it as
   `bytea` on the wire and fails** — cast to `string(...)` first.
4. `store/postgres/migrations/000N_<name>.up.sql` + `.down.sql`.
5. Wire into `Config`, `Engine`, and the `cryden` facade.

**Error patterns:**
- Simple binary failure → sentinel `var ErrX = errors.New(...)`.
- Failure that carries data the caller needs → a struct type with an
  `Error()` method, retrieved via `errors.As` (see
  `ErrSecondFactorRequired{PendingToken, Methods}`,
  `ErrPasswordPolicyViolation{Violations []string}`,
  `ErrOAuthEmailConflict`). Never encode structured data into an error
  *string* for a caller to parse.
- Enumeration-avoidance: when a wrong input and a nonexistent-resource
  input would otherwise return different errors or take different
  time, they must return the identical error AND the identical
  execution path (see `Login`'s nonexistent-email case, which still
  pays bcrypt's cost via a dummy hash — a fixed historical bug, worth
  reading `auth/login.go`'s comment on it once).

**Audit logging:** every security-relevant event gets an
`AuditEventType` constant in `store/interfaces.go` and is recorded via
`store.AuditStore`. Routine input-validation failures (a malformed
email, a too-short password) are NOT audited — too noisy, not
security-relevant. A confirmed breach, a failed second-factor attempt,
a completed login, an account lock — those are.

**Second-factor gate:** every *primary* authentication path (password
`Login`, `CompleteMagicLink`, `LoginWithOAuth`) routes through
`completePrimaryAuth` in `auth/login.go`. It collects confirmed
methods (`totp`, `webauthn`, `recovery_code` — the last **only**
alongside a real factor, never standalone, see the comment there for
why) and either pauses with `*ErrSecondFactorRequired{PendingToken,
Methods}` or calls `finishLogin` to issue tokens. **Any new primary
auth method MUST route through `completePrimaryAuth`, never
reimplement session issuance inline** — `LoginWithOAuth` shipped with
exactly that bug once; it's fixed now, don't reintroduce the pattern.

**Encryption vs. hashing:** passwords, tokens, recovery codes →
one-way hash (bcrypt for passwords; SHA-256 via `token.HashToken` for
everything else, since those are already high-entropy random values,
not human-guessable secrets — bcrypt's slow-hash property defends
against a different threat than these need). TOTP secrets and WebAuthn
ceremony state → `security.Encryptor` (reversible), because the engine
must recover the original plaintext value later. Never mix these up.

**Fixed, non-configurable security TTLs:** `mfaPendingTTL` (5 min),
`magicLinkTTL` (15 min) are intentionally hardcoded constants, not
`Config` fields. A tuning knob here just invites a deployment to widen
a narrow security window. Follow this precedent for any new short-
lived credential — don't make it configurable without a real reason.

## Known platform gotchas (don't rediscover these)

- No network access to `proxy.golang.org` in some sandboxed tool
  environments — `go build`/`go test`/`go mod tidy` may not be
  runnable there. Say so plainly; don't claim untested code compiles.
- `lib/pq` fails outright on Termux/Android (`os/user.Current`
  unimplemented for `GOOS=android`) — not something to fix, the human
  works around it with `proot-distro ubuntu` or a real machine.
- Supabase connection strings must use the **session pooler** (port
  5432), not the transaction pooler (6543) or a direct connection.
- `virtualwebauthn`'s simulated credential starts its signature
  counter at 0 and never auto-increments on its own — and 0 is itself
  a legitimate, spec-allowed value for a real authenticator too. Don't
  assert a counter "must be nonzero" in any WebAuthn test; if you need
  to test counter pass-through, set it explicitly before the call.
- **Never mutate the real `crypto/rand.Reader` package-level global in
  a test**, on any platform — on at least one real environment, a
  failed read through that specific global hits the Go runtime's own
  unrecoverable fatal-error path (a process crash, not a normal test
  failure), not a catchable error. If you need to test an entropy-read
  failure path, inject a fake `io.Reader` into a same-package struct
  field instead (see `token.CryptoRandTokenGenerator.randReader` for
  the pattern).
- **When you change a shared function's signature, grep the ENTIRE
  repo for every call site before committing** —
  `grep -rn "FunctionName(ctx" --include="*.go" .` — not just the
  files you remember touching. This exact mistake (a test file on an
  earlier branch not updated when a later, stacked branch changed a
  signature it also called) has shipped twice already in this
  project's history and only surfaced when `go test ./...` ran after
  merging.

## What's already shipped (Tier 1, tagged v2.2.0)

Signup/login/logout, account lockout, email verification/change,
OAuth (Google/GitHub, provider-agnostic design — adding a new provider
string needs zero engine changes), TOTP 2FA, WebAuthn passkeys
(second-factor only, not passwordless-primary yet), magic-link login,
recovery codes, breached-password checking (interface-only), password
policy (secure-by-default). Full detail in each feature's README
section and `docs/testing/*.md`. Don't re-verify any of this is
working — `CURRENT-STATE.md` confirms it's tagged and done.
