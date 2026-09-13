# Security Policy

CrydenSync is an authentication library, security issues here can affect real production systems and real users' credentials. Please report responsibly.

## Reporting a Vulnerability

**Do not open a public GitHub issue** for a security vulnerability. Instead, report it privately via:

- **GitHub's private vulnerability reporting**: Security tab → "Report a vulnerability"
- **Email**: devraymond24@gmail.com

### Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce, or a minimal proof-of-concept if possible
- The version/commit of CrydenSync affected

## What to Expect

This is currently a solo-maintained open source project, I can't promise enterprise-grade SLAs, but I take security reports seriously and will:

1. **Acknowledge** your report as soon as I can, typically within a few days
2. **Investigate** and confirm the issue
3. **Work on a fix** and coordinate disclosure timing with you before any public write-up
4. **Credit you** in the release notes, if you'd like

Please give a reasonable amount of time to fix a confirmed issue before any public disclosure.

## Scope

### In Scope
- The core engine (`auth/`, `token/`, `session/`, `security/`, `store/`, Postgres and SQLite implementations), `notify/`, `logger/`
- The read-only admin tooling (`admin/`, `ai/`, `widget/`), including any bug that would let one of these take an action, not just read/report
- Anything that could lead to authentication bypass, token forgery, privilege escalation, information disclosure, or similar

### Out of Scope
- Vulnerabilities in a consuming application's own code, configuration, or infrastructure (e.g. a leaked `JWT_SECRET`, a misconfigured database, a consuming app not validating input before passing it to CrydenSync)
- Vulnerabilities in third-party dependencies, please report those upstream as well, but let me know if CrydenSync needs to update a pinned version in response
- The (separate, not-yet-built) CLI, HTTP API, or SDK repositories, report those against the relevant repo once they exist

## Supported Versions

Only the latest tagged v2.x.x release receives security fixes. As of this writing that's v2.5.x, which is expected to be the version for a while, the engine's feature backlog is complete through Tier 4 and no new tier is planned without an explicit go-ahead.

## Design Notes for Security Reviewers

A few things worth knowing if you're reviewing this codebase:

- **Refresh tokens** are hashed (SHA-256) before storage, the raw token is never persisted
- **Refresh token rotation** includes reuse detection: presenting an already-rotated token revokes the entire session family, not just that token
- **No default JWT secret** exists anywhere, the engine fails construction if one isn't explicitly provided
- **Account lockout** is DB-backed (not in-memory), so it holds across restarts and multiple instances
- `ChangePassword` and `DeleteAccount` require re-confirmation of the current password, not just a valid access token
- **`admin/`, `ai/`, `widget/` are structurally read-only**, narrow interfaces with no write method, so a bug here cannot lock an account or change config on its own. A report that one of these can be made to act, not just read, is treated as a vulnerability
- **`widget.Ask`** force-scopes every query to the calling end user's own data before validation runs, regardless of what a model's parsed output claims, a report that a crafted question can read another user's data is high priority
