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

## Running against SQLite

A second real backend, not a fallback — a single file, no server to run. All storage interfaces are implemented in `store/sqlite`:

```go
import (
	"database/sql"

	_ "modernc.org/sqlite" // pick any driver you like — mattn, modernc, ncruces; the package imports none itself
	"github.com/crydensync/cryden/v2/store/sqlite"
)

db, err := sql.Open("sqlite", "file:cryden.db?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
if err := sqlite.Migrate(context.Background(), db); err != nil { /* ... */ }

engine, err := cryden.New(cryden.Config{
	JWTSecret: os.Getenv("JWT_SECRET"),
	Users:     sqlite.NewUserStore(db),
	Sessions:  sqlite.NewSessionStore(db),
	Audit:     sqlite.NewAuditStore(db),
})
```

Nothing outside `store/sqlite` changed to support this — no interface, no facade function, no `auth`/`session`/`security` code can tell which backend it's holding. `sqlite.CheckPragmas(ctx, db)` reports whether `foreign_keys` and a busy timeout are actually active on your connection (pragmas are per-connection, and `*sql.DB` is a pool, so this is worth checking rather than assuming). Foreign keys are off by default in SQLite, so `UserStore.Delete` cascades sessions/tokens/etc. by hand in a transaction rather than relying on the database to do it.

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

**On custom email content:** there's no `Config.EmailSubject` or template knob, and there won't be one added casually — `SendVerification`/`SendMagicLink` hand you `(ctx, to, rawToken)` and nothing else, so you already have full control over subject, body, HTML, language, and the actual URL from inside your own `EmailSender`/`MagicLinkSender` implementation. See `docs/testing/custom-email-templates.md` for a worked example (two languages, two providers).

## OAuth (Google, GitHub, or any provider)

The engine never performs an HTTP redirect and never talks to a specific provider — that's inherently HTTP-shaped work that belongs in your API layer. By the time you call into the engine, your app has already completed the provider's redirect/callback flow and confirmed the person's identity. `provider` is a plain string the engine never validates against a fixed list, so Google, GitHub, Microsoft, Discord, GitLab, Apple, or anything else you support all work identically — there is nothing provider-specific inside the engine to add:

```go
engine, err := cryden.New(cryden.Config{
	// ...required fields...
	OAuth: postgres.NewOAuthStore(db), // or memory.NewOAuthStore()
})

tokens, err := cryden.LoginWithOAuth(ctx, engine, "google", externalID, email, callerIP, userAgent)
// or "microsoft", "discord", "gitlab", "apple", ... — same call, same behavior
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

Once confirmed, `Login` no longer issues tokens directly for that account — it returns `*auth.ErrSecondFactorRequired` (retrievable via `errors.As`) carrying a short-lived pending token and the list of enrolled second-factor methods:

```go
tokens, err := cryden.Login(ctx, engine, email, password, callerIP, userAgent)

var secondFactor *auth.ErrSecondFactorRequired
if errors.As(err, &secondFactor) {
	// secondFactor.Methods is e.g. []string{"totp"} — prompt accordingly, then:
	tokens, err = cryden.CompleteLoginWithTOTP(ctx, engine, secondFactor.PendingToken, code, callerIP, userAgent)
}
```

The pending token expires after 5 minutes and is only ever valid for completing that one login — it's a distinct token type from an access token, not just a permissive one. `DisableTOTP(ctx, engine, userID, currentPassword)` removes 2FA from an account and requires the current password as re-confirmation. Calling any TOTP function without `Config.TOTP` set returns `cryden.ErrTOTPNotConfigured`.

## Passkeys (WebAuthn, as a second factor)

Passkeys are supported as an additional second-factor method, unified with TOTP under the same `*auth.ErrSecondFactorRequired` pause state — an account can have TOTP, a passkey, both, or neither; `Login` reports whichever are enrolled via `Methods` and the caller picks. (Passwordless *primary* login via passkeys — no password step at all — isn't built yet; this is 2FA on top of a password, same as TOTP.)

Requires four additional `Config` fields, all required together:

```go
engine, err := cryden.New(cryden.Config{
	// ...required fields, EncryptionKey (shared with TOTP if both are configured)...
	WebAuthn:              postgres.NewWebAuthnStore(db), // or memory.NewWebAuthnStore()
	WebAuthnRPID:          "yourapp.com",                 // your real domain — see note below
	WebAuthnRPDisplayName: "Your App Inc",                // shown in the browser's passkey prompt
	WebAuthnRPOrigins:     []string{"https://yourapp.com"},
})
```

`WebAuthnRPID` is a genuine security parameter, not cosmetic like `TOTPIssuerName` — passkeys are cryptographically bound to it, and a credential registered against one RPID will never validate against another. `WebAuthnRPOrigins` must exactly match what the browser actually sends.

Registration is a begin/finish ceremony — the engine never talks to the browser directly, it only produces and consumes the JSON payloads:

```go
creationOptionsJSON, ceremonyToken, err := cryden.BeginRegisterPasskey(ctx, engine, userID)
// forward creationOptionsJSON to the browser's navigator.credentials.create() call

err = cryden.FinishRegisterPasskey(ctx, engine, userID, ceremonyToken, clientResponseJSON, "MacBook Touch ID")
// clientResponseJSON is the raw JSON body the browser call resolved with
```

`ceremonyToken` is the WebAuthn ceremony's own short-lived challenge state, encrypted with the same `EncryptionKey` used for TOTP secrets — pass it through unmodified, there's no separate ephemeral store to manage.

Login completion is a three-call sequence — `Login` pauses the same way it does for TOTP, but the passkey ceremony itself is its own begin/finish round trip on top of that:

```go
tokens, err := cryden.Login(ctx, engine, email, password, callerIP, userAgent)

var secondFactor *auth.ErrSecondFactorRequired
if errors.As(err, &secondFactor) {
	// secondFactor.Methods might be []string{"webauthn"} or []string{"totp", "webauthn"}
	assertionOptionsJSON, ceremonyToken, err := cryden.BeginWebAuthnLogin(ctx, engine, secondFactor.PendingToken)
	// forward assertionOptionsJSON to navigator.credentials.get()

	tokens, err = cryden.CompleteLoginWithWebAuthn(ctx, engine, secondFactor.PendingToken, ceremonyToken, clientResponseJSON, callerIP, userAgent)
}
```

`ListPasskeys(ctx, engine, userID)` lists registered passkeys (nickname, creation time, last used). `DeletePasskey(ctx, engine, userID, credentialID, currentPassword)` removes one — requires the current password, same reasoning as `DisableTOTP`. Calling any passkey function without `Config.WebAuthn` set returns `cryden.ErrWebAuthnNotConfigured`.

## Magic-link (passwordless) login

Requires one additional `Config` field:

```go
engine, err := cryden.New(cryden.Config{
	// ...required fields, and Verifications (shared with email-change tokens)...
	MagicLinkSender: yourMagicLinkSender, // implements notify.MagicLinkSender
})
```

`MagicLinkSender` is a separate interface from `EmailSender` — not a new method added to it, since `EmailSender` already shipped and adding a required method would break every existing implementation. `Config.Verifications` must also be set; magic-link tokens reuse the same store email-change tokens use, distinguished by purpose internally.

This logs in an **existing account only** — it doesn't create one:

```go
err := cryden.RequestMagicLink(ctx, engine, email, callerIP)
// always nil for a nonexistent email too (avoids leaking which emails are registered);
// a real delivery failure for an existing account still returns as an error

tokens, err := cryden.CompleteMagicLink(ctx, engine, rawTokenFromTheLink, callerIP, userAgent)
```

The link is valid for 15 minutes and single-use — clicking it a second time fails the same way an expired one does. Like `Login`, `CompleteMagicLink` routes through the same second-factor gate: an account with TOTP/a passkey enrolled returns `*auth.ErrSecondFactorRequired` here exactly as it would after a correct password — clicking the link proves email ownership, the primary factor, not a bypass of a confirmed second one. Calling either function without `Config.MagicLinkSender` set returns `cryden.ErrMagicLinkNotConfigured`.

## Recovery (backup) codes

Requires one additional `Config` field:

```go
engine, err := cryden.New(cryden.Config{
	// ...required fields...
	RecoveryCodes: postgres.NewRecoveryCodeStore(db), // or memory.NewRecoveryCodeStore()
})
```

Generating a batch requires the account to already have a confirmed TOTP secret or a registered passkey — codes exist to recover access to a *real* second factor, not to stand in as one on their own:

```go
codes, err := cryden.GenerateRecoveryCodes(ctx, engine, userID)
// show `codes` to the user ONCE — the engine only ever stores their hashes
// and can never display them again after this call returns
```

Generating a fresh batch always replaces the previous one in full — every old code, used or not, stops working immediately. Completion works the same way TOTP does:

```go
tokens, err := cryden.CompleteLoginWithRecoveryCode(ctx, engine, secondFactor.PendingToken, code, callerIP, userAgent)
```

**One safety property worth knowing:** `"recovery_code"` only ever appears in `Login`'s `Methods` list *alongside* `"totp"` and/or `"webauthn"` — never on its own. If an account's last real second factor gets disabled while unconsumed codes still exist in storage, those codes stop being offered at all, rather than silently becoming a standalone permanent backdoor into the account. Calling either function without `Config.RecoveryCodes` set returns `cryden.ErrRecoveryCodesNotConfigured`.

## Breached-password check

```go
engine, err := cryden.New(cryden.Config{
	// ...required fields...
	BreachedPasswordChecker: yourChecker, // implements security.BreachedPasswordChecker
})
```

Ships **zero implementations** — checking a password against a breach database means an outbound network call (e.g. to [HIBP's Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords), which uses k-anonymity so you never send the actual password), and the engine doesn't talk to the internet on its own initiative anywhere else in this codebase, so it doesn't start here either. A minimal HIBP implementation looks roughly like:

```go
type hibpChecker struct{ client *http.Client }

func (h *hibpChecker) IsBreached(ctx context.Context, password string) (bool, error) {
	sum := sha1.Sum([]byte(password))
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := hash[:5], hash[5:]

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.pwnedpasswords.com/range/"+prefix, nil)
	resp, err := h.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return strings.Contains(string(body), suffix), nil
}
```

Checked on `SignUp` and `ChangePassword`, after the password policy (cheap, local checks first) and after `ChangePassword`'s current-password verification (a new password's breach status should never leak to someone who hasn't already proven they own the account). **A checker error fails open** — SignUp/ChangePassword proceed rather than blocking on a third-party API's uptime; only a confirmed breach (`true, nil`) rejects the password with `auth.ErrPasswordBreached`.

## Password policy

```go
engine, err := cryden.New(cryden.Config{
	// ...required fields...
	PasswordPolicy: security.PasswordPolicy{
		MinLength:        12,
		RequireUppercase: true,
		RequireDigit:     true,
	},
})
```

Unlike TOTP/WebAuthn/recovery codes, this has **no "unconfigured means off" state** — leaving `PasswordPolicy` as the zero value applies `security.DefaultPasswordPolicy` instead (`MinLength: 8, MaxLength: 72`, no character-class requirements, following NIST 800-63B guidance that length matters far more than forced complexity rules). `MaxLength` defaults to 72 specifically because that's bcrypt's own real limit — without this check, a longer password hits a raw bcrypt library error at hash time instead of a clean validation error.

A violation returns `*auth.ErrPasswordPolicyViolation{Violations []string}` — every broken rule at once (`"min_length"`, `"max_length"`, `"require_uppercase"`, `"require_lowercase"`, `"require_digit"`, `"require_symbol"`), not just the first one hit, so you can show a user everything wrong with their password in one pass instead of a fix-resubmit-discover-the-next-problem loop. These are stable machine-readable codes, not display strings — the engine doesn't own UI copy or localization anywhere else, so it doesn't start here either.

## Password hashing: bcrypt or Argon2id

Argon2id is a second real implementation of `security.Hasher`, not a replacement for bcrypt — both satisfy the same `Hash`/`Compare` surface, and nothing in the engine can tell which one a given stored hash used:

```go
argon2id, err := security.NewArgon2idHasher(security.DefaultArgon2idParams)

engine, err := cryden.New(cryden.Config{
	// ...required fields...
	Hasher: argon2id, // or leave unset for bcrypt
})
```

Verification is stateless — every hash names its own algorithm and parameters in its encoded form (`$argon2id$v=19$m=…,t=…,p=…$salt$key` vs. bcrypt's own format), so a table holding hashes from both algorithms (mid-migration, or forever) needs no extra column to track which is which. If you switch `Config.Hasher` on an existing user base, accounts get upgraded to the new algorithm automatically the next time they log in successfully — fire-and-forget, so a storage hiccup during the upgrade never blocks the login it rode in on. "Out of date" means weaker only (a lower cost/memory parameter than your current config), never merely different, so a hardware change alone won't churn every hash in your database.

## Anomaly detection

Report-only signal collection over login attempts: new IP for this account, new device (parsed from the user-agent) for this account, unusually high failure velocity for a user or an IP, refresh-token reuse, and an unusual number of concurrent sessions. Six signal codes ship: `new_ip`, `new_device`, `user_failure_velocity`, `ip_failure_velocity`, `token_reuse`, `concurrent_sessions`.

```go
engine, err := cryden.New(cryden.Config{
	// ...required fields...
	Anomalies:         postgres.NewAnomalyStore(db), // or memory.NewAnomalyStore()
	AnomalyThresholds: security.DefaultAnomalyThresholds, // optional — tune sensitivity
})
```

Runs inside every primary login path (password, magic-link, OAuth) automatically once configured. **A flagged attempt is never blocked** — it's recorded as an `anomaly_detected` audit event with the signal(s) attached, and your application decides what to do with that information (step-up verification, an alert, nothing at all). Nil-safe: leave `Anomalies` unset and this is simply off, with zero behavior change anywhere else. Impossible-travel/geo-distance detection was deliberately left out — it needs an outbound call to a geo-IP service, which is exactly what `Config.Geolocator` below is for, kept as a separate, optional concern.

## Credential-stuffing detection

The attack anomaly detection's per-account view structurally can't see: one IP trying one leaked password against many different accounts, where each account only ever sees a single failure. Reads the same login-attempt history anomaly detection already records — no second tracking system:

```go
engine, err := cryden.New(cryden.Config{
	// ...required fields, and Anomalies (this reuses that store)...
	CredentialStuffingThresholds: security.DefaultCredentialStuffingThresholds,
})
```

Flags an `account_spray` when one IP's distinct-account failure breadth crosses the threshold within the configured window, with `unknown_account_spray` as a qualifier when most of that spray hit addresses with no real account behind them. Same report-only contract as anomaly detection — a `credential_stuffing_detected` audit event, never a block — and a configurable cooldown collapses a sustained spray into one event per IP rather than one per attempt.

## Named/fingerprinted sessions

Turns a bare session ID into something a person recognizes at a glance — "Chrome on macOS, San Francisco" instead of a UUID — computed on read from the `IP`/`UserAgent` every session already stores, so there's no migration and no new column:

```go
sessions, err := cryden.ListNamedSessions(ctx, engine, userID)
for _, s := range sessions {
	fmt.Println(s.Label) // e.g. "Chrome on macOS · San Francisco, US"
}
```

Device parsing (browser/OS/form factor) ships as real engine code — it needs nothing beyond the user-agent string the engine already has. Geolocation is interface-only, **zero shipped implementations** — placing an IP means an outbound call or a licensed database, so it follows the same rule as `BreachedPasswordChecker`:

```go
engine, err := cryden.New(cryden.Config{
	// ...required fields...
	Geolocator: myGeolocatorImpl, // implements security.IPGeolocator
})
```

Leave `Geolocator` unset and labels are device-only ("Chrome on macOS") with nothing else changing; a geolocator error costs that one label, never the listing itself.

## Rate limiting: in-memory or Redis

The default rate limiter keeps its counters in a Go map, which is correct for exactly one running instance — three replicas behind a load balancer keep three independent maps, so a configured limit of 10 actually lets 30 through. `security.RedisRateLimiter` is a second real implementation of the same `security.RateLimiter` interface, sharing counters across every instance:

```go
import "github.com/redis/go-redis/v9"

limiter, err := security.NewRedisRateLimiter(redisClient, 10, time.Minute) // 10 attempts per minute, shared

engine, err := cryden.New(cryden.Config{
	// ...required fields...
	RateLimiter: limiter, // or leave unset for the single-instance in-memory default
})
```

Injected already-constructed, exactly like every store — the engine never dials Redis itself or owns the connection's lifecycle. `NewRedisRateLimiter` accepts any `redis.Scripter` (a plain `*redis.Client`, `*redis.ClusterClient`, `*redis.Ring`, or `*redis.UniversalClient` all work). **Fail-closed and load-bearing**: `SignUp`, `Login`, and `RequestMagicLink` all propagate a limiter error rather than silently allowing the request through, so once configured, Redis becomes a hard dependency of those three calls — wrap it yourself if you'd rather fail open on a Redis outage.

## Structured logging & cloud log integrations

`Logger` itself ships **zero vendor implementations** — Datadog, Better Stack, and every other hosted log vendor are an outbound HTTPS call with their own batching/retry/payload rules, the same reasoning that keeps `BreachedPasswordChecker` and `IPGeolocator` implementation-free. Stdout-as-JSON (the existing default) is already the universal integration point any log shipper can tail. What the `logger` package adds instead are the pieces every host hits immediately when wiring a real sink up:

```go
import "github.com/crydensync/cryden/v2/logger"

hashedRedactor, err := logger.NewHashingRedactor(consoleLogger, os.Getenv("LOG_HASH_KEY"), logger.DefaultRedactedKeys()...)

myLogger := logger.NewMultiLogger(
	logger.NewLevelFilter(myVendorLogger, logger.LevelWarn), // only warnings and above reach the vendor
	hashedRedactor, // ip/user_id fields keyed-HMAC-hashed before hitting your local console
)

engine, err := cryden.New(cryden.Config{
	// ...required fields...
	Logger: myLogger, // implements logger.Logger, optionally logger.ContextLogger for trace correlation
})
```

`ContextLogger` is a separate, optional interface (`Logger` itself stays frozen so no existing implementation breaks) — implement it and the engine hands your sink the request's `context.Context` for trace-ID correlation, once per facade call. Two `Redactor` constructors are available — `NewMaskingRedactor` (replaces a value with `[redacted]`) and `NewHashingRedactor` (keyed HMAC-SHA256, never a plain unkeyed hash — the IPv4 space is small enough that an unkeyed digest of an address is just a lookup table away from the address). `NewMultiLogger` fans one log line out to as many wrapped loggers as you give it.

## Extensible JWT claims

`Config.AccessTokenClaims` lets your application attach its own data (roles, permissions, tenant ID — whatever your authorization layer needs) to every access token the engine issues, on both the initial login and every subsequent refresh:

```go
engine, err := cryden.New(cryden.Config{
	// ...required fields...
	AccessTokenClaims: myClaimsProviderFunc, // implements token.ClaimsProvider: func(ctx, userID) (map[string]any, error)
})

userID, claims, err := cryden.VerifyTokenWithClaims(engine, tokens.AccessToken)
// claims has your custom fields, with the registered JWT claim names already stripped out
```

All seven RFC 7519 §4.1 registered claim names (`sub`, `iss`, `aud`, `exp`, `nbf`, `iat`, `jti`) are refused, all-or-nothing, if your provider tries to set any of them — `sub` in particular is what `Verify` reads the authenticated user ID from, so a provider able to overwrite it could mint a token authenticating as someone else. **A provider error fails the token issuance** — deliberately the opposite of `BreachedPasswordChecker`'s fail-open, since a silently missing claim is an absence a downstream authorization check might read as permission rather than as an error. A nil `AccessTokenClaims` is byte-for-byte today's behavior.

## API keys (machine-to-machine auth)

A credential for a caller with no human behind it — a CI pipeline, a backend service, a cron job — deliberately outside the second-factor system entirely: no `Login`, no pending-token pause, nothing that would prompt a machine for a code it can't produce.

```go
engine, err := cryden.New(cryden.Config{
	// ...required fields...
	APIKeys: postgres.NewAPIKeyStore(db), // or memory.NewAPIKeyStore()
})

rawKey, key, err := cryden.GenerateAPIKey(ctx, engine, userID, "CI pipeline", []string{"deploy"}, 0) // ttl of 0 means it never expires
// rawKey looks like ck_<64 hex chars> — shown to you exactly once; only its hash is ever stored
// key.ID is what RevokeAPIKey takes; key.Prefix ("ck_9f3a1c02") is safe to show in a list

identity, err := cryden.AuthenticateAPIKey(ctx, engine, presentedKey)
// identity.UserID, identity.KeyID, identity.Name, identity.Scopes

keys, err := cryden.ListAPIKeys(ctx, engine, userID)
err = cryden.RevokeAPIKey(ctx, engine, userID, key.ID)
```

Scopes are opaque strings you define — `identity.HasScope("deploy")` is exact-match only, no hierarchy, no wildcards; the engine never interprets what a scope means. Password lockout does **not** apply to keys (so failing a developer's password five times can't also take down that developer's production integrations), and there's deliberately no rate limiting on the authenticate path itself (limiting by key requires hashing and looking the key up first, at which point the expensive part is already done). Every failure on the read path — unknown, revoked, expired, malformed — returns the same `auth.ErrInvalidAPIKey`, so a caller holding a stolen key can't use error responses to sort which ones are still live.

## Webhooks

The engine tells your application what happened instead of waiting to be polled. `notify.WebhookSender` ships **zero implementations** — same shape as `EmailSender` and `IPGeolocator`:

```go
engine, err := cryden.New(cryden.Config{
	// ...required fields...
	Webhooks:      myWebhookSenderImpl, // implements notify.WebhookSender: SendWebhook(ctx, notify.WebhookEvent) error
	WebhookEvents: cryden.DefaultWebhookEvents(), // optional — defaults to this if Webhooks is set and WebhookEvents isn't
})
```

`DefaultWebhookEvents()` is sixteen events bounded by real human action — deliberately excluding `login_success`, `token_rotated`, and `login_failed`, since those fire at a volume that scales with your traffic (or with whoever's attacking you) rather than with anything a webhook receiver typically wants pinged about. There's intentionally no "send everything" switch, since that would silently start delivering new event types the moment a future engine version adds them, without you ever having decided that. Delivery is synchronous on the request path immediately after the audit write — the interface's own doc comment says to enqueue rather than make the real HTTP call inline — and a delivery error is logged but never fails the operation it's attached to.

## AI-assisted admin features

Four read-only tools built on top of the engine's own audit history and current settings — **none of them can take an action.** There is no code path anywhere in any of the four that locks an account, changes a config value, or does anything beyond reading and reporting; a human (or, for the widget, a host application's end user reading their own data) is always the one who acts on what these return.

### Weekly digest

```go
report, err := cryden.WeeklyDigest(ctx, engine)          // last 7 days
report, err := cryden.DigestSince(ctx, engine, someTime) // a window you choose
fmt.Println(report) // plain English, fixed section order, a quiet week renders as two lines
```

### Support-ticket assistant

Turns "why can't user X log in" into an answer read entirely from what's already recorded — account lock state, recent failed/rejected second-factor attempts, and current session state — never anything it has to guess at:

```go
report, err := cryden.DiagnoseLoginIssue(ctx, engine, "someone@example.com")
fmt.Println(report) // paste straight into the support ticket
```

### Config tuning advisor

Reads 30 days of audit history against your current settings (lockout threshold, rate limiter, anomaly/credential-stuffing detection, breached-password checking) and suggests changes worth considering — never applies any of them:

```go
report, err := cryden.ConfigTuningReport(ctx, engine)
fmt.Println(report) // e.g. "Rate limiting: using the default in-memory limiter... consider a Redis-backed one"
```

### Ask-AI widget

The one piece of this tier meant for a host application's **own end users**, not just admins — which makes prompt injection a real threat model rather than a theoretical one. Built on the `ai` package's existing allowlisted query machinery (`ai.LLMProvider`, `ai.QueryableStore` — both ship **zero implementations**, bring your own model and your own read-only DB role) plus one new, mandatory layer: `widget.Ask` force-scopes every query to the asking end user's own data, in code, regardless of what a model's parsed output claims:

```go
import "github.com/crydensync/cryden/v2/widget"

answer, err := widget.Ask(ctx, widget.Config{
	Provider: myLLMProvider,    // ai.LLMProvider — your model call
	Store:    myQueryableStore, // ai.QueryableStore — a read-only DB role
	Composer: myComposer,       // optional; nil falls back to a deterministic plain-text rendering
}, currentUserID, question)    // currentUserID MUST come from your own auth, never from question
```

The security property this buys: a successful prompt injection can change what query a model *tries* to produce — asking about another user's sessions, say — but it cannot change what the code lets that query actually read, because the identity filter is overwritten unconditionally rather than trusted or merely validated. There's no way to reach a "you tried to access someone else's data" error either, by design — every phrasing of a question, honest or adversarial, produces the exact same query, scoped to `currentUserID`, so there's no oracle for an attacker to learn anything from trying. Full reasoning in `docs/design/ask-ai-widget.md`.

## What's in v2

**Auth & login**
- Signup, login, logout (single device + all devices)
- OAuth login/signup with any provider (Google, GitHub, Microsoft, Discord, GitLab, Apple, ...) with explicit, non-auto-linking account collision handling — see [OAuth](#oauth-google-github-or-any-provider)
- Two-factor authentication: TOTP and passkeys (WebAuthn), unified under one pause state — see [Two-factor authentication](#two-factor-authentication-totp) and [Passkeys](#passkeys-webauthn-as-a-second-factor)
- Magic-link (passwordless) login for existing accounts, routed through the same second-factor gate — see [Magic-link login](#magic-link-passwordless-login)
- Recovery (backup) codes as a second-factor fallback, with a safety guard against becoming a standalone backdoor once the real factor is removed — see [Recovery codes](#recovery-backup-codes)
- Breached-password checking (interface-only, bring your own HIBP/etc.) and a configurable, secure-by-default password policy — see [Breached-password check](#breached-password-check) and [Password policy](#password-policy)

**Security & monitoring**
- Anomaly detection — new IP/device, failure velocity, token reuse, unusual concurrent sessions — report-only, never blocks — see [Anomaly detection](#anomaly-detection)
- Credential-stuffing detection — one IP spraying many accounts, which per-account lockout structurally can't see — see [Credential-stuffing detection](#credential-stuffing-detection)
- Named/fingerprinted sessions ("Chrome on macOS · San Francisco") computed on read, no migration — see [Named sessions](#namedfingerprinted-sessions)
- Redis-backed rate limiter as a drop-in second implementation of the same interface, for correctness across more than one running instance — see [Rate limiting](#rate-limiting-in-memory-or-redis)

**Infrastructure & extensibility**
- Argon2id as a second password hasher alongside bcrypt, with format-sniffing verification and automatic upgrade-on-login — see [Password hashing](#password-hashing-bcrypt-or-argon2id)
- A second full storage backend, SQLite, alongside Postgres — same interfaces, single-file deployment — see [Running against SQLite](#running-against-sqlite)
- Cloud logger integration primitives (level filtering, redaction, fan-out) — interface-only, bring your own vendor sink — see [Structured logging](#structured-logging--cloud-log-integrations)
- Extensible JWT claims — attach your own authorization data to every access token, registered claim names always protected — see [Extensible JWT claims](#extensible-jwt-claims)
- API keys for machine-to-machine auth, deliberately outside the second-factor system — see [API keys](#api-keys-machine-to-machine-auth)
- Webhooks — the engine notifies your app of key events instead of waiting to be polled — see [Webhooks](#webhooks)

**AI-assisted admin tooling** (see [AI-assisted admin features](#ai-assisted-admin-features)) — all four are read-only/surface-only by design; none can lock an account, change a config value, or take any action
- Weekly digest — plain-English activity summary
- Support-ticket assistant — "why can't user X log in," answered from what's already recorded
- Config tuning advisor — suggests changes against 30 days of history, never applies them
- Ask-AI widget — the one piece exposed to a host app's own end users, with identity-scoping enforced in code against prompt injection
- `ai` subpackage — the allowlisted, read-only query safety layer the widget and any custom admin tooling are built on

**Core**
- JWT access tokens + rotating opaque refresh tokens with theft/reuse detection
- Session listing and revocation
- Change password (requires current password, revokes all other sessions)
- Change email (requires verification of the new address before it takes effect)
- Delete account (requires current password)
- Persistent, DB-backed account lockout after repeated failed login attempts — survives restarts, correct across multiple instances
- Email verification primitives (token issue/confirm) — delivery is pluggable via the `notify.EmailSender` interface, the engine never sends email itself
- Audit logging
- Pagination and system-wide read facades (`ListAll`, `Count`, `CountActive`, `SearchByType`, `GetUser`, `ListPublicSessions`) for building admin tooling on top of the engine
- Two storage backends: Postgres and SQLite (interface-based, more can be added later)

## What's not in v2 (yet)

CLI, HTTP API, and language SDKs are separate repositories that wrap this engine — this repo is the core library only. SMS OTP, SAML, organizations/multi-tenancy, SSO via OIDC, RBAC/permissions, and data export/delete-my-data are all explicitly out of scope for the current backlog pending. Passkeys are currently second-factor only — passwordless *primary* login via passkeys (no password step at all) is a planned fast-follow now that magic-link forced the shared "login without a password" plumbing to exist.

## License

MIT — see [LICENSE](./LICENSE).

---

<div align="center">
  <sub>Built with ❤️ in Africa · Own your users, not vendor lock-in</sub>
</div>
