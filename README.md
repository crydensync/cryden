# CrydenSync

<div align="center">
	
[![Go Reference](https://pkg.go.dev/badge/github.com/crydensync/cryden/v2.svg)](https://pkg.go.dev/github.com/crydensync/cryden/v2)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Stars](https://img.shields.io/github/stars/crydensync/cryden?style=social)](https://github.com/crydensync/cryden/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/crydensync/cryden?style=social)](https://github.com/crydensync/cryden/network/members)
</div>

**An embeddable, framework-agnostic authentication engine for Go. Import it, configure it, own your users.**

```go
import "github.com/crydensync/cryden/v2"
```

## Why

Every project ends up rewriting auth from scratch, or handing user data to a third-party provider. CrydenSync is a library, not a service — your users, sessions, and audit logs stay in your own database, under your own control.

- **Own your users** — no hosted service, no data leaving your infrastructure
- **No vendor lock-in** — plain Postgres tables, no proprietary format
- **Framework-agnostic** — no request/response objects, no assumptions about your HTTP layer
- **Zero telemetry** — the engine never phones home. Logs and audit events go wherever *you* wire them, never to us

## Install

```bash
go get github.com/crydensync/cryden/v2
```

## Quickstart

Runs with zero setup using the in-memory store — good for trying it out or writing tests:

```go
package main

import (
	"context"
	"os"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store/memory"
)

func main() {
	ctx := context.Background()

	engine, err := cryden.New(cryden.Config{
		JWTSecret: os.Getenv("JWT_SECRET"),
		Users:     memory.NewUserStore(),
		Sessions:  memory.NewSessionStore(),
		Audit:     memory.NewAuditStore(),
	})
	if err != nil {
		panic(err)
	}

	user, err := cryden.SignUp(ctx, engine, "proguy@example.com", "Pass@2026", "1.2.3.4")
	if err != nil {
		panic(err)
	}

	tokens, err := cryden.Login(ctx, engine, "proguy@example.com", "Pass@2026", "1.2.3.4", "some-user-agent")
	if err != nil {
		panic(err)
	}

	userID, err := cryden.VerifyToken(engine, tokens.AccessToken)
	_ = user
	_ = userID
}
```

## Running against Postgres

1. Run the migration in `store/postgres/migrations/0001_initial_schema.up.sql` against your database.
2. Requires Postgres 13+ (uses the built-in `gen_random_uuid()`).
3. Swap the memory stores for the Postgres ones:

```go
import (
	"database/sql"

	_ "github.com/lib/pq"
	"github.com/crydensync/cryden/v2/store/postgres"
)

db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))

engine, err := cryden.New(cryden.Config{
	JWTSecret: os.Getenv("JWT_SECRET"),
	Users:     postgres.NewUserStore(db),
	Sessions:  postgres.NewSessionStore(db),
	Audit:     postgres.NewAuditStore(db),
})
```

Works with any standard Postgres — Supabase, Neon, RDS, self-hosted, etc. If your provider offers both a direct and a connection-pooled URL, use the direct (or session-mode pooled) connection string — the engine relies on multi-statement transactions during token rotation, which can misbehave under transaction-mode pgbouncer poolers.

## Account lockout

After repeated failed login attempts, an account is locked for a configurable duration — persistent in the database, not in-memory, so it holds even through restarts or multiple running instances. Defaults to 5 attempts / 15 minutes; override via `Config.LockoutThreshold` and `Config.LockoutDuration`.

## Email verification / email change

`RequestEmailChange` and `ConfirmEmailChange` require two additional `Config` fields that are otherwise optional:

```go
engine, err := cryden.New(cryden.Config{
	// ...required fields...
	Verifications: postgres.NewVerificationStore(db), // or memory.NewVerificationStore()
	EmailSender:   myEmailSenderImpl,                  // you implement notify.EmailSender
})
```

The engine never sends email itself — implement `notify.EmailSender` against whatever provider you use (SendGrid, SES, SMTP), and build the actual verification URL yourself; the engine only hands you a raw token, it has no idea what your app's domain or routes look like. Calling `RequestEmailChange` without these configured returns `cryden.ErrEmailChangeNotConfigured` rather than panicking.

## OAuth (Google, GitHub, or any provider)

The engine never performs an HTTP redirect and never talks to a specific provider — that's inherently HTTP-shaped work that belongs in your API layer. By the time you call into the engine, your app has already completed the provider's redirect/callback flow and confirmed the person's identity:

```go
engine, err := cryden.New(cryden.Config{
	// ...required fields...
	OAuth: postgres.NewOAuthStore(db), // or memory.NewOAuthStore()
})

tokens, err := cryden.LoginWithOAuth(ctx, engine, "google", externalID, email, callerIP, userAgent)
```

`LoginWithOAuth` also doubles as signup — if neither an existing link nor an existing account matches, a new user is created automatically. If the email matches an existing password-based account that isn't linked yet, it returns `*auth.ErrOAuthEmailConflict` (retrievable via `errors.As`) rather than auto-linking — auto-linking on email match alone is an account-takeover vector if a provider's email verification ever has an edge case. Resolve it by having the person log in with their password first, then call:

```go
err := cryden.LinkOAuthIdentity(ctx, engine, userID, "google", externalID, email, callerIP)
```

`userID` must come from an already-verified session — never trust an email alone to authorize a link. Calling either function without `Config.OAuth` set returns `cryden.ErrOAuthNotConfigured`.

## Two-factor authentication (TOTP)

Requires two additional `Config` fields:

```go
engine, err := cryden.New(cryden.Config{
	// ...required fields...
	TOTP:           postgres.NewTOTPStore(db), // or memory.NewTOTPStore()
	EncryptionKey:  os.Getenv("ENCRYPTION_KEY"), // separate secret from JWTSecret
	TOTPIssuerName: "YourApp", // shown in the user's authenticator app
})
```

`EncryptionKey` is required whenever `TOTP` is set — a TOTP secret has to be recoverable in plaintext to validate codes against it, so (unlike passwords and tokens) it's encrypted rather than hashed. Use a different value from `JWTSecret`, not the same one twice.

Enrollment is a two-step confirm flow — a secret never gates login until the user proves they've actually captured it:

```go
otpauthURL, err := cryden.EnrollTOTP(ctx, engine, userID)
// render otpauthURL as a QR code for the user to scan

err = cryden.ConfirmTOTP(ctx, engine, userID, codeFromApp)
// only after this succeeds does the account require a code to log in
```

Once confirmed, `Login` no longer issues tokens directly for that account — it returns `*auth.ErrTOTPRequired` (retrievable via `errors.As`) carrying a short-lived pending token:

```go
tokens, err := cryden.Login(ctx, engine, email, password, callerIP, userAgent)

var totpRequired *auth.ErrTOTPRequired
if errors.As(err, &totpRequired) {
	// prompt for a code, then:
	tokens, err = cryden.CompleteLoginWithTOTP(ctx, engine, totpRequired.PendingToken, code, callerIP, userAgent)
}
```

The pending token expires after 5 minutes and is only ever valid for completing that one login — it's a distinct token type from an access token, not just a permissive one. `DisableTOTP(ctx, engine, userID, currentPassword)` removes 2FA from an account and requires the current password as re-confirmation. Calling any TOTP function without `Config.TOTP` set returns `cryden.ErrTOTPNotConfigured`.

## AI-assisted admin queries (library support only)

The `ai` subpackage provides the safety machinery for natural-language admin tooling — an allowlisted `QueryIntent` type, `validateIntent`, and `ExecuteQuery` — plus `store/postgres.SafeQueryStore`, a read-only query executor. This is a foundation for tools like `csax`'s CLI to build on, not a feature you call directly in application code. An LLM's output is treated as untrusted data to validate against a strict allowlist, never as SQL to execute — and the actual DB connection passed to `SafeQueryStore` must be opened with a read-only Postgres role, since that's the real safety boundary, not just the allowlist check. `ai.LLMProvider` ships zero implementations; bring your own (OpenAI, Anthropic, OpenRouter, a local model).

## What's in v2

- Signup, login, logout (single device + all devices)
- OAuth login/signup (Google, GitHub, or any provider) with explicit, non-auto-linking account collision handling — see [OAuth](#oauth-google-github-or-any-provider)
- Two-factor authentication (TOTP) with encrypted-at-rest secrets and a confirm-before-enforce enrollment flow — see [Two-factor authentication](#two-factor-authentication-totp)
- JWT access tokens + rotating opaque refresh tokens with theft/reuse detection
- Session listing and revocation
- Change password (requires current password, revokes all other sessions)
- Change email (requires verification of the new address before it takes effect)
- Delete account (requires current password)
- Persistent, DB-backed account lockout after repeated failed login attempts — survives restarts, correct across multiple instances
- Email verification primitives (token issue/confirm) — delivery is pluggable via the `notify.EmailSender` interface, the engine never sends email itself
- Rate limiting, bcrypt password hashing, audit logging
- Pagination and system-wide read facades (`ListAll`, `Count`, `CountActive`, `SearchByType`, `GetUser`, `ListPublicSessions`) for building admin tooling on top of the engine
- `ai` subpackage — allowlisted, read-only query safety layer for AI-assisted admin tooling built on top of this engine (see [AI-assisted admin queries](#ai-assisted-admin-queries-library-support-only))
- One storage backend: Postgres (interface-based, more can be added later)

## What's not in v2 (yet)

CLI, HTTP API, and language SDKs are separate repositories that wrap this engine — this repo is the core library only. Magic links, SMS OTP, WebAuthn, SAML, and other advanced auth methods are planned for later releases.

## License

MIT — see [LICENSE](./LICENSE).

---

<div align="center">
  <sub>Built with ❤️ in Africa · Own your users, not vendor lock-in</sub>
</div>
