package core

import (
	"context"
	"fmt"
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
	PasswordPolicy PasswordPolicy
	JWTSecret      string
	TokenExpiry    time.Duration
}

// New creates a new authentication engine
func New(users UserStore, sessions SessionStore) *Engine {
	return &Engine{
		users:       users,
		sessions:    sessions,
		hasher:      NewBcryptHasher(10),
		rateLimiter: NewMemoryRateLimiter(5, time.Minute), // 5 attempts per minute
		auditLogger: NewConsoleAuditLogger(),              //default
		config: Config{
			PasswordPolicy: DefaultPasswordPolicy(),
			JWTSecret:      "change-this-in-production", // TODO: make configurable
			TokenExpiry:    15 * time.Minute,
		},
	}
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

// SignUp creates a new user account
func (e *Engine) SignUp(ctx context.Context, email, password string) (*User, error) {
	// Validate email
	if err := ValidateEmail(email); err != nil {
		return nil, err
	}

	// Validate password
	if err := ValidatePassword(password, e.config.PasswordPolicy); err != nil {
		return nil, err
	}

	// Check if user already exists
	existing, err := e.users.GetByEmail(ctx, email)
	if err != nil && err != ErrUserNotFound {
		return nil, err
	}
	if existing != nil {
		e.auditLogger.Log(ctx, AuditEntry{
			Timestamp: time.Now(),
			Action:    ActionSignUp,
			Status:    "FAILED",
			Error:     "email already exist",
			Metadata:  map[string]interface{}{"email": email},
		})
		return nil, ErrUserExists
	}

	// Hash password
	hash, err := e.hasher.Hash(password)
	if err != nil {
		return nil, err
	}

	// Create user
	user, err := e.users.Create(ctx, email, hash)
	if err != nil {
		return nil, err
	}
	e.auditLogger.Log(ctx, AuditEntry{
		Timestamp: time.Now(),
		UserID:    user.ID,
		Action:    ActionSignUp,
		Status:    "SUCCESS",
		IPAddress: getClientIP(ctx),
	})

	return user, nil
}

// Login authenticates a user and returns tokens
func (e *Engine) Login(ctx context.Context, email, password string) (*TokenPair, *LimitResult, error) {
	key := "login:" + getClientIP(ctx)

	// Check rate rate limit
	result, err := e.rateLimiter.Allow(ctx, key)
	if err != nil {
		return nil, &result, err
	}
	fmt.Printf("Login attempt - Allowed: %v, Remaining: %d\n", result.Allowed, result.Remaining)

	if !result.Allowed {
		e.auditLogger.Log(ctx, AuditEntry{
			Timestamp: time.Now(),
			Action:    ActionRateLimited,
			Status:    "BLOCKED",
			IPAddress: getClientIP(ctx),
			Metadata: map[string]interface{}{
				"remainig": result.Remaining,
				"reset":    result.Reset,
			},
		})
		return nil, &result, ErrTooManyAttempts
	}

	// Find user
	user, err := e.users.GetByEmail(ctx, email)
	if err != nil {
		if err == ErrUserNotFound {
			e.auditLogger.Log(ctx, AuditEntry{
				Timestamp: time.Now(),
				Action:    ActionSignInFailed,
				Status:    "FAILED",
				Error:     "user not found",
				IPAddress: getClientIP(ctx),
			})
			return nil, &result, ErrInvalidCredentials // Don't reveal user doesn't exist
		}
		return nil, &result, err
	}

	// Check password - USE HASHER
	if err := e.hasher.Compare(password, user.PasswordHash); err != nil {
		e.auditLogger.Log(ctx, AuditEntry{
			Timestamp: time.Now(),
			UserID:    user.ID,
			Action:    ActionSignInFailed,
			Status:    "FAILED",
			Error:     "wrong password",
			IPAddress: getClientIP(ctx),
		})
		return nil, &result, ErrInvalidCredentials
	}

	// Create session
	session, err := e.sessions.Create(ctx, user.ID)
	if err != nil {
		return nil, &result, err
	}

	e.auditLogger.Log(ctx, AuditEntry{
		Timestamp: time.Now(),
		UserID:    user.ID,
		Action:    ActionSignInSuccess,
		Status:    "SUCCESS",
		IPAddress: getClientIP(ctx),
	})

	// Generate tokens (simplified for now)
	tokens := &TokenPair{
		AccessToken:  "jwt_" + generateID(), // Will make real JWT later
		RefreshToken: session.RefreshToken,
	}

	return tokens, &result, nil
}

// Helper to generate IDs (move to a utils file later)
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// getClientIP extracts IP from context (simplified for now)
func getClientIP(ctx context.Context) string {
	// For now, return a fixed string
	// Later, we'll extract from context
	return "127.0.0.1"
}
