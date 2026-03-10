# Contributing to CrydenSync 

First off, thank you for considering contributing to Cryden! 🎉

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## 🌍 Our Philosophy

Cryden is built for developers worldwide, with special consideration for:
- **Offline-first development** — Works without internet
- **Low-bandwidth environments** — Small binary size
- **Developer ownership** — Your users belong to you
- **Simplicity** — Easy to understand and extend

## 🚀 Getting Started

### Prerequisites
- Go 1.21 or higher
- Git
- Make (optional)

### Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/cryden.git
   cd cryden
```

1. Install dependencies:
   ```bash
   go mod download
   ```
2. Run tests:
   ```bash
   go test ./internal/tests/... -v
   ```
3. Run the example:
   ```bash
   cd examples/complete
   go run main.go
   ```

🧪 Testing Guidelines

Write Tests First

We practice test-driven development where possible:

```go
func TestNewFeature(t *testing.T) {
    // 1. Setup
    engine := cryden.New()
    
    // 2. Test the feature
    result, err := engine.NewFeature()
    
    // 3. Assert
    if err != nil {
        t.Errorf("Expected no error, got %v", err)
    }
    if result == nil {
        t.Error("Expected result, got nil")
    }
}
```

Test Coverage

· Aim for 80%+ coverage
· Use go test -cover to check
· New features must include tests

Mocking

Use interfaces for mocking:

```go
type MockUserStore struct {
    users map[string]*User
}

func (m *MockUserStore) GetByEmail(email string) (*User, error) {
    if user, ok := m.users[email]; ok {
        return user, nil
    }
    return nil, ErrUserNotFound
}
```

💅 Coding Standards

Go Style

· Follow Go Code Review Comments
· Run go fmt before committing
· Use golangci-lint for additional checks

Naming Conventions

· Interfaces: UserStore, Hasher, AuditLogger
· Methods: SignUp, Login, LogoutAll
· Errors: ErrUserNotFound, ErrInvalidToken
· Tests: TestLogin, TestChangePassword/success

Documentation

· All exported functions must have comments
· Examples should be runnable
· Update relevant docs when adding features

🔧 Pull Request Process

1. Create an issue first for discussion
2. Fork and branch (feature/your-feature or fix/your-fix)
3. Write code with tests
4. Run tests locally:
   ```bash
   make test
   ```
5. Update documentation if needed
6. Push and create PR
7. Address review comments

PR Checklist

· Tests pass
· Code is formatted
· Documentation updated
· Commit messages clear
· No unrelated changes

📝 Commit Messages

Follow Conventional Commits:

```
feat: add logout all devices
^──^  ^─────────────────^
|     |
|     └─ Description in imperative mood
|
└─ Type: feat, fix, docs, style, refactor, test, chore
```

Examples:

· feat: add rate limiting headers
· fix: handle nil session in logout
· docs: update getting started guide
· test: add mfa test cases
· refactor: extract token generation

🚀 Release Process

Maintainers follow:

1. Update version in go.mod
2. Update CHANGELOG.md
3. Create git tag: git tag v1.0.0
4. Push tag: git push origin v1.0.0
5. GitHub Actions creates release

📚 Documentation Contributions

Markdown Style

· One sentence per line (easier diffs)
· Use code blocks with language
· Include working examples
· Link to related docs

Adding Examples

Each example should:

· Be in examples/ directory
· Have a main.go that runs
· Include comments
· Be referenced in docs

🐛 Reporting Bugs

Include:

· Cryden version
· Go version
· Database being used
· Minimal reproduction code
· Expected vs actual behavior

💡 Feature Requests

Tell us:

· What problem you're solving
· How it fits Cryden's philosophy
· Example usage
· Why existing solutions don't work

🌟 Recognition

Contributors will be:

· Listed in CONTRIBUTORS.md
· Mentioned in release notes
· Thanked in community spaces

📞 Getting Help

· Issues: GitHub issues
· Discussions: GitHub Discussions
· Twitter: @crydensync
· Email: contributors@cryden.dev

🎉 Thank You!

Your contributions make CrydenSync better for everyone, especially developers in:

· 🌍 Africa (offline-first, low bandwidth)
· 🚀 Startups (no vendor lock-in)
· 🧑‍💻 Indie developers (free, open source)

---

<div align="center">
  <sub>Made with ❤️ by the CrydenSync community</sub>
</div>
```
