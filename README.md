# CrydenSync

<div align="center">
	
[![Go Reference](https://pkg.go.dev/badge/github.com/crydensync/cryden/v2.svg)](https://pkg.go.dev/github.com/crydensync/cryden/v2)
[![Go Report Card](https://goreportcard.com/badge/github.com/crydensync/cryden/v2)](https://goreportcard.com/report/github.com/crydensync/cryden/v2)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<!-- Social Stats - These will show numbers even if zero -->
[![GitHub Stars](https://img.shields.io/github/stars/crydensync/cryden?style=social)](https://github.com/crydensync/cryden/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/crydensync/cryden?style=social)](https://github.com/crydensync/cryden/network/members)
[![GitHub Watchers](https://img.shields.io/github/watchers/crydensync/cryden?style=social)](https://github.com/crydensync/cryden/watchers)
[![GitHub Downloads](https://img.shields.io/github/downloads/crydensync/cryden/total)](https://github.com/crydensync/cryden/releases)
</div>

An embeddable, framework-agnostic authentication engine for Go. Import it, configure it, own your users.

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

## What's in v2

- Signup, login, logout (single device + all devices)
- JWT access tokens + rotating opaque refresh tokens with theft/reuse detection
- Session listing and revocation
- Change password (requires current password, revokes all other sessions)
- Change email (requires verification of the new address before it takes effect)
- Delete account (requires current password)
- Persistent, DB-backed account lockout after repeated failed login attempts — survives restarts, correct across multiple instances
- Email verification primitives (token issue/confirm) — delivery is pluggable via the `notify.EmailSender` interface, the engine never sends email itself
- Rate limiting, bcrypt password hashing, audit logging
- One storage backend: Postgres (interface-based, more can be added later)

## What's not in v2 (yet)

CLI, HTTP API, and language SDKs are separate repositories that wrap this engine — this repo is the core library only. OAuth (Google/GitHub), MFA, magic links, SMS OTP, WebAuthn, SAML, and other advanced auth methods are planned for later releases.

## License

MIT — see [LICENSE](./LICENSE).

---

<div align="center">
  <sub>Built with ❤️ in Africa · Own your users, not vendor lock-in</sub>
</div>
