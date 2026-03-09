# CrydenSync 🔐

<div align="center">

**Embeddable authentication engine for Go — offline-first, framework-agnostic.**

[![Go Reference](https://pkg.go.dev/badge/github.com/crydensync/cryden.svg)](https://pkg.go.dev/github.com/crydensync/cryden)
[![Go Report Card](https://goreportcard.com/badge/github.com/crydensync/cryden)](https://goreportcard.com/report/github.com/crydensync/cryden)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Release](https://img.shields.io/github/v/release/crydensync/cryden)](https://github.com/crydensync/cryden/releases)
[![Build Status](https://github.com/crydensync/cryden/actions/workflows/test.yml/badge.svg)](https://github.com/crydensync/cryden/actions/workflows/test.yml)

</div>

## 🎯 The Problem

Authentication is not business logic, yet every project rewrites it. Developers face three painful choices:

1. **Rewrite auth logic** for every project — risky, inconsistent, time-consuming
2. **Use hosted auth services** — vendor lock-in, users aren't yours, requires internet
3. **Use framework-specific tools** — tied to Express, Django, Next.js — not reusable

## 💡 The Solution

CrydenSync is an **embeddable authentication engine** that gives you a standard, reusable auth system you control:

```go
import "github.com/crydensync/cryden"

func main() {
    engine := cryden.New()  // In-memory for testing
    
    // Or with persistent storage
    // engine, _ := cryden.WithSQLite("users.db")
    
    ctx := context.Background()
    
    // Sign up
    user, _ := cryden.SignUp(ctx, engine, "alice@example.com", "SecurePass123")
    
    // Login
    tokens, _, _ := cryden.Login(ctx, engine, "alice@example.com", "SecurePass123")
    
    // Protect routes
    userID, _ := cryden.VerifyToken(engine, tokens.AccessToken)
}
```

✨ Features

✅ v1.0.0 (Current)

· Email/password authentication — Secure, bcrypt hashed
· JWT access tokens — Short-lived, stateless
· Opaque refresh tokens — Stored in DB for revocation
· Rate limiting — Per IP with headers (X-RateLimit-*)
· Audit logging — Track every auth event
· Session management — Logout single device or all devices
· Multiple storage backends — Memory, SQLite, PostgreSQL, MongoDB
· Complete test suite — 90%+ coverage
· Offline-first — Works without internet, SQLite by default

🚧 Coming Soon

Feature Status Target
gRPC API 🚧 Planned v1.1.0
CLI tool (csax) 🚧 Planned v1.1.0
Language SDKs (JS, Python, PHP) 🚧 Planned v1.2.0
MFA/2FA (TOTP) 📅 Future v1.3.0
Magic Links 📅 Future v1.3.0
WebAuthn/Passkeys 📅 Future v2.0.0

📦 Installation

```bash
go get github.com/crydensync/cryden@v1.0.0
```

📖 Documentation

Section Description
📚 Getting Started 60-second working auth
🎯 Philosophy Why Cryden exists
🏗️ Architecture How it works
📐 Design Decisions Why we built it this way
🔧 Guide Installation, config, middleware, testing
🔌 Adapters Interface implementations
📘 API Reference Complete API docs
💡 Examples Copy-paste working code

🧪 Testing

CrydenSync is designed for maximum testability:

```go
func TestLogin(t *testing.T) {
    engine := cryden.New()  // In-memory storage
    
    // Optional: Use mock hasher for faster tests
    engine.WithHasher(&core.MockHasher{})
    
    // Optional: Disable rate limiting
    engine.WithRateLimiter(&core.NoopRateLimiter{})
    
    ctx := context.Background()
    cryden.SignUp(ctx, engine, "test@example.com", "pass")
    tokens, _, err := cryden.Login(ctx, engine, "test@example.com", "pass")
    
    assert.NoError(t, err)
    assert.NotEmpty(t, tokens.AccessToken)
}
```

📖 Testing Guide →

🔧 Configuration

```go
// With SQLite persistence
engine, err := cryden.WithSQLite("users.db")

// With custom JWT secret (required in production)
cryden.WithJWTSecret(engine, os.Getenv("JWT_SECRET"))

// With custom rate limiter
engine.WithRateLimiter(redis.NewRateLimiter())

// With custom audit logger
engine.WithAuditLogger(file.NewAuditLogger("auth.log"))
```

📊 Storage Backends

Backend Status Use Case
Memory ✅ Stable Testing
SQLite ✅ Stable Offline-first, development
PostgreSQL ✅ Stable Production
MongoDB ✅ Stable Document stores
MySQL 🚧 Planned v1.1.0
Redis 🚧 Planned v1.1.0 (rate limiting)

## 📛 About the Name

**CrydenSync** is the full name of the project, but the Go package is simply `cryden` for brevity.

```go
import "github.com/crydensync/cryden"  // Notice: crydensync/cryden

auth := cryden.New()  // Short and sweet!
``````

## 🔒 Security Notes v1.0.0

### ✅ Implemented
- Password hashing with bcrypt
- JWT signing with HMAC-SHA256
- Rate limiting to prevent brute force
- Audit logging for all auth events

### ⚠️ Planned for v1.1.0
- Refresh token hashing in database
- Session token hashing
- Device fingerprinting
- Argon2id hasher option

### Future Security Enhancements
- Email verification (v1.1)
- Password reset flow (v1.1)
- MFA/2FA (v1.2)
- Login notifications (v1.2)
- Breached password detection (v1.2)

### 🔐 Best Practices
1. Always use HTTPS in production
2. Set strong JWT secrets via environment variables
3. Monitor audit logs for suspicious activity
4. Add email verification before sensitive actions

🤝 Contributing

We welcome contributions! See CONTRIBUTING.md for:

· Code of Conduct
· Development setup
· Pull request process
· Coding standards

📄 License

MIT © Crydensync

⭐ Support

If you find Cryden useful, please star the repo!

## 🗺️ Roadmap

### Current: v1.0.0 (March 2026)
✅ Core authentication with email/password
✅ JWT + refresh tokens
✅ Rate limiting & audit logs
✅ Multiple databases (SQLite, PostgreSQL, MongoDB)

### Coming in v1.1.0 (Q2 2026)
🚀 CLI tool (`csax`)
📱 Device tracking (IP, user agent, last seen)
🔐 Argon2id hasher
⚡ Redis rate limiter
le audit logger
🐬 MySQL support

### Coming in v1.2.0 (Q3 2026)
🔌 gRPC API
🌐 Language SDKs (JS, Python, PHP)
🔔 Webhooks
🔄 Migration tools (Clerk, Auth0, Supabase)

### Coming in v1.3.0 (Q4 2026)
🔐 Multi-Factor Authentication (TOTP)
📧 Magic links & passwordless
🔑 WebAuthn / Passkeys
🌍 Social login (OAuth2)

### Future (2027+)
☁️ Optional cloud sync
📊 Enterprise features
🔌 More adapters
🚀 v2.0.0 (breaking changes if needed)

[View full roadmap →](docs/roadmap.md)

---

<div align="center">
  <sub>Built with ❤️ in Africa · Own your users, not vendor lock-in</sub>
</div>
```
