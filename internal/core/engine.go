package core

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
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

// DefautConfig returns sensible defaults
func DefautConfig() Config {
	return Config{
		PasswordPolicy:  DefaultPasswordPolicy(),
		JWTSecret:       "change-this-in-production", // WARNING Change this!
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
		rateLimiter: NewMemoryRateLimiter(5, time.Minute), // 5 attempts per minute
		auditLogger: NewConsoleAuditLogger(),              //default
		config:      DefautConfig(),
	}
}

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
	/*session err := e.sessions.Create(ctx, user.ID)
	if err != nil {
		return nil, &result, err
	}
	*/

	e.auditLogger.Log(ctx, AuditEntry{
		Timestamp: time.Now(),
		UserID:    user.ID,
		Action:    ActionSignInSuccess,
		Status:    "SUCCESS",
		IPAddress: getClientIP(ctx),
	})

	// Generate tokens (simplified for now)
	//tokens := &TokenPair{
	//AccessToken:  "jwt_" + generateID(), // Will make real JWT later
	//RefreshToken: session.RefreshToken,
	//}

	tokens, err := e.generateTokens(ctx, user.ID)
	if err != nil {
		return nil, &result, err
	}

	// Reset rate limit on SUCCESS
	//e.rateLimiter.Reset(ctx, key)

	return tokens, &result, nil
}

// generateTokens creates JWT access token and refresh token
func (e *Engine) generateTokens(ctx context.Context, userID string) (*TokenPair, error) {
	// Generate JWT access token
	now := time.Now()
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(e.config.AccessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    e.config.Issuer,
			Subject:   userID,
			ID:        generateID(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString([]byte(e.config.JWTSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Create session with refresh token
	session, err := e.sessions.Create(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: session.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(e.config.AccessTokenTTL.Seconds()),
	}, nil
}

// VerifyToken validates a JWT  access token
func (e *Engine) VerifyToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpedted signing method: %v", token.Header["alg"])
		}
		return []byte(e.config.JWTSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("faied to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, ErrInvalidToken
}

func (e *Engine) RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error) {
	// Find session
	session, err := e.sessions.GetByRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Check if expired
	if time.Now().After(session.ExpiresAt) {
		e.sessions.Revoke(ctx, session.ID)
		return nil, ErrInvalidToken
	}

	// Generate new tokens
	tokens, err := e.generateTokens(ctx, session.UserID)
	if err != nil {
		return nil, err
	}

	// Revoke old session (security - token rotation)
	e.sessions.Revoke(ctx, session.ID)

	// Audit
	e.auditLogger.Log(ctx, AuditEntry{
		Timestamp: time.Now(),
		UserID:    session.UserID,
		Action:    ActionTokenRefresh,
		Status:    "SUCCESS",
	})

	return tokens, nil
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

// Authenticate extracts user ID from token
func (e *Engine) Authenticate(tokenString string) (string, error) {
	claims, err := e.VerifyToken(tokenString)
	if err != nil {
		return "", err
	}
	return claims.UserID, nil
}

// Logout revokes the current session
func (e *Engine) Logout(ctx context.Context, refreshToken string) error {
    session, err := e.sessions.GetByRefreshToken(ctx, refreshToken)
    if err != nil {
        return ErrInvalidToken
    }

    if err := e.sessions.Revoke(ctx, session.ID); err != nil {
        return err
    }

    e.auditLogger.Log(ctx, AuditEntry{
        Timestamp: time.Now(),
        UserID:    session.UserID,
        Action:    ActionSignOut,
        Status:    "SUCCESS",
        IPAddress: getClientIP(ctx),
    })

    return nil
}

// LogoutAll revokes ALL sessions for a user
func (e *Engine) LogoutAll(ctx context.Context, userID string) error {
    if err := e.sessions.RevokeAllForUser(ctx, userID); err != nil {
        return err
    }

    e.auditLogger.Log(ctx, AuditEntry{
        Timestamp: time.Now(),
        UserID:    userID,
        Action:    ActionSignOutAll,
        Status:    "SUCCESS",
        IPAddress: getClientIP(ctx),
    })

    return nil
}

// ChangePassword updates user's password and logs out all devices
func (e *Engine) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
    // 1. Get user
    user, err := e.users.GetByID(ctx, userID)
    if err != nil {
        return err
    }

    // 2. Verify old password
    if err := e.hasher.Compare(oldPassword, user.PasswordHash); err != nil {
        e.auditLogger.Log(ctx, AuditEntry{
            Timestamp: time.Now(),
            UserID:    userID,
            Action:    ActionPasswordChange,
            Status:    "FAILED",
            Error:     "wrong old password",
        })
        return ErrInvalidCredentials
    }

    // 3. Validate new password
    if err := ValidatePassword(newPassword, e.config.PasswordPolicy); err != nil {
        return err
    }

    // 4. Hash new password
    newHash, err := e.hasher.Hash(newPassword)
    if err != nil {
        return err
    }

    // 5. Update in database
    if err := e.users.UpdatePassword(ctx, userID, newHash); err != nil {
        return err
    }

    // 6. Logout all devices (security best practice)
    e.sessions.RevokeAllForUser(ctx, userID)

    // 7. Audit success
    e.auditLogger.Log(ctx, AuditEntry{
        Timestamp: time.Now(),
        UserID:    userID,
        Action:    ActionPasswordChange,
        Status:    "SUCCESS",
    })

    return nil
}

// ChangeEmail updates user's email
func (e *Engine) ChangeEmail(ctx context.Context, userID, newEmail string) error {
    // 1. Validate email
    if err := ValidateEmail(newEmail); err != nil {
        return err
    }

    // 2. Check if email already exists
    existing, err := e.users.GetByEmail(ctx, newEmail)
    if err != nil && err != ErrUserNotFound {
        return err
    }
    if existing != nil {
        return ErrUserExists
    }

    // 3. Update email
    if err := e.users.UpdateEmail(ctx, userID, newEmail); err != nil {
        return err
    }

    // 4. Audit log
    e.auditLogger.Log(ctx, AuditEntry{
        Timestamp: time.Now(),
        UserID:    userID,
        Action:    ActionEmailChange,
        Status:    "SUCCESS",
        Metadata: map[string]interface{}{
            "new_email": newEmail,
        },
    })

    return nil
}

// DeleteAccount removes user and all sessions
func (e *Engine) DeleteAccount(ctx context.Context, userID string) error {
    // 1. Delete all sessions first
    e.sessions.RevokeAllForUser(ctx, userID)

    // 2. Delete user
    if err := e.users.Delete(ctx, userID); err != nil {
        return err
    }

    // 3. Audit log
    e.auditLogger.Log(ctx, AuditEntry{
        Timestamp: time.Now(),
        UserID:    userID,
        Action:    ActionAccountDelete,
        Status:    "SUCCESS",
    })

    return nil
}
