# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-03-08

### 🚀 Initial Release

#### Added
- Core authentication engine
- Email/password signup and login
- JWT access token generation and verification
- Opaque refresh tokens with database storage
- Rate limiting with memory implementation
- Audit logging with console output
- Session management (create, revoke, list)
- Multiple storage backends:
  - In-memory (testing)
  - SQLite (offline-first)
  - PostgreSQL (production)
  - MongoDB (document stores)
- Complete test suite with 90%+ coverage
- Examples for all features

#### Features
- `SignUp` - Create new user accounts
- `Login` - Authenticate and get tokens
- `Logout` - Revoke current session
- `LogoutAll` - Revoke all user sessions
- `ChangePassword` - Update with old password verification
- `ChangeEmail` - Update user email
- `DeleteAccount` - Remove user and all sessions
- `RefreshToken` - Get new tokens with rotation
- `VerifyToken` - Validate JWT and get user ID

#### Developer Experience
- Clean public API at `cryden/`
- Interface-driven design for easy mocking
- In-memory stores for fast tests
- Comprehensive documentation
- Working examples

#### Documentation
- Getting started guide
- Philosophy and design decisions
- Architecture overview
- API reference
- Testing guide
- Contribution guidelines

[1.0.0]: https://github.com/crydensync/cryden/releases/tag/v1.0.0

