# Contributing to CrydenSync

Thanks for your interest in contributing. This document covers how the project is structured and what's expected of a change before it's merged.

## Project structure

CrydenSync is an embeddable, framework-agnostic Go authentication engine. Key principles that shape every contribution:

- **Interface-first** — every component (storage, hashing, rate limiting, ID/token generation, logging) is defined as an interface before it's implemented. See `store/interfaces.go`, `security/*.go`, `logger/logger.go`.
- **One production implementation per interface in v1/v2** — this keeps the core lean. New backend implementations (a second `UserStore`, a different `RateLimiter`, etc.) are welcome, but should be proposed via an issue first so we can agree on the interface shape before code is written.
- **No storage-specific types leak into interfaces** — interface methods take and return plain domain types (`store.User`, `store.Session`, primitives), never `*sql.DB`, `*pgxpool.Pool`, or similar. This is what keeps implementations swappable.
- **Framework-agnostic** — the engine never infers caller context (IP, user agent, etc.) internally. Anything like that is an explicit parameter passed in by the caller.
- **Security-critical config fails loud** — no default JWT secret, no silent fallback for anything security-relevant. If in doubt, an error is safer than a default.

## Before you open a PR

1. **Open an issue first** for anything beyond a small fix — bug fixes, typos, and doc corrections can go straight to a PR, but new features or interface changes should be discussed first.
2. **Tests are required**, not optional, for any change to `auth/`, `token/`, `session/`, or `security/` — these are the security-critical packages. A PR touching refresh token rotation, password hashing, or session ownership checks without a corresponding test will be asked to add one before merge.
3. **Run the full suite before submitting:**
   ```bash
   go build ./...
   go vet ./...
   go test ./...
   ```
4. **Keep PRs focused.** One logical change per PR — easier to review, easier to revert if something's wrong.

## Reporting a security issue

Please do **not** open a public issue for a security vulnerability. See `SECURITY.md` (or contact the maintainer directly) for responsible disclosure.

## Code style

- Standard `gofmt`/`goimports` formatting — no exceptions.
- Prefer explicit, narrow function parameters over passing around large structs, especially in `auth/`, `session/`, and `token/` — makes each function easy to test in isolation.
- Comment the *why*, not the *what*, especially around security decisions (e.g. why an error is generic instead of specific, why a check happens before another).

## Code of Conduct

By participating in this project, you agree to abide by the [Code of Conduct](./CODE-OF-CONDUCT.md).