package core

import (
    "context"
    "time"
)

// Engine is the main authentication engine
type Engine struct {
    users       UserStore
    sessions    SessionStore
    hasher      Hasher
    rateLimiter RateLimiter
    auditLogger AuditLogger
    config      Config
}

// Config holds engine configuration
type Config struct {
    PasswordPolicy  PasswordPolicy
    JWTSecret       string
    AccessTokenTTL  time.Duration
    RefreshTokenTTL time.Duration
    Issuer          string
    TokenExpiry     time.Duration
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
    return Config{
        PasswordPolicy:  DefaultPasswordPolicy(),
        JWTSecret:       "change-this-in-production",
        AccessTokenTTL:  15 * time.Minute,
        RefreshTokenTTL: 7 * 24 * time.Hour,
        Issuer:          "cryden",
    }
}

// New creates a new authentication engine
func New(users UserStore, sessions SessionStore) *Engine {
    return &Engine{
        users:       users,
        sessions:    sessions,
        hasher:      NewBcryptHasher(10),
        rateLimiter: NewMemoryRateLimiter(5, time.Minute),
        auditLogger: NewConsoleAuditLogger(),
        config:      DefaultConfig(),
    }
}

// Configuration setters
func (e *Engine) WithJWTSecret(secret string) *Engine {
    e.config.JWTSecret = secret
    return e
}

func (e *Engine) WithHasher(hasher Hasher) *Engine {
    e.hasher = hasher
    return e
}

func (e *Engine) WithRateLimiter(limiter RateLimiter) *Engine {
    e.rateLimiter = limiter
    return e
}

func (e *Engine) WithAuditLogger(logger AuditLogger) *Engine {
    e.auditLogger = logger
    return e
}

// Getter methods for testing
func (e *Engine) GetUserStore() UserStore {
    return e.users
}

func (e *Engine) GetSessionStore() SessionStore {
    return e.sessions
}
