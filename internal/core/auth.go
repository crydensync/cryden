package core

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

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
func (e *Engine) Login(ctx context.Context, email, password string, deviceInfo *DeviceInfo, ipAddress string) (*TokenPair, *LimitResult, error) {
    key := "login:" + getClientIP(ctx)

    // Check rate limit
    result, err := e.rateLimiter.Allow(ctx, key)
    if err != nil {
        return nil, &result, err
    }

    if !result.Allowed {
        e.auditLogger.Log(ctx, AuditEntry{
            Timestamp: time.Now(),
            Action:    ActionRateLimited,
            Status:    "BLOCKED",
            IPAddress: getClientIP(ctx),
            Metadata: map[string]interface{}{
                "remaining": result.Remaining,
                "reset":     result.Reset,
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
            return nil, &result, ErrInvalidCredentials
        }
        return nil, &result, err
    }

    // Check password
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

    // Generate tokens
    tokens, err := e.generateTokens(ctx, user.ID, deviceInfo, ipAddress)
    if err != nil {
        return nil, &result, err
    }

    // Reset rate limit on success
    //e.rateLimiter.Reset(ctx, key)

    e.auditLogger.Log(ctx, AuditEntry{
        Timestamp: time.Now(),
        UserID:    user.ID,
        Action:    ActionSignInSuccess,
        Status:    "SUCCESS",
        IPAddress: getClientIP(ctx),
    })

    return tokens, &result, nil
}

// RefreshToken issues new tokens and rotates the refresh token
func (e *Engine) RefreshToken(ctx context.Context, plainToken string) (*TokenPair, error) {
    // Generate lookup hash from plain token
    sha := sha256.Sum256([]byte(plainToken))
    lookupHash := hex.EncodeToString(sha[:])

    // Find session by lookup hash
    session, err := e.sessions.GetByRefreshToken(ctx, lookupHash)
    if err != nil {
        return nil, ErrInvalidToken
    }

    // Verify the token matches the stored hash
    if err := e.hasher.Compare(plainToken, session.RefreshToken); err != nil {
        e.auditLogger.Log(ctx, AuditEntry{
            Timestamp: time.Now(),
            UserID:    session.UserID,
            Action:    "TOKEN_TAMPERING",
            Status:    "BLOCKED",
        })
        e.sessions.Revoke(ctx, session.ID)
        return nil, ErrInvalidToken
    }

    // Check expiration
    if time.Now().After(session.ExpiresAt) {
        e.sessions.Revoke(ctx, session.ID)
        return nil, ErrInvalidToken
    }

    // Generate new tokens (this creates a new session)
    newTokens, err := e.generateTokens(ctx, session.UserID)
    if err != nil {
        return nil, err
    }

    // Revoke old session
    if err := e.sessions.Revoke(ctx, session.ID); err != nil {
        // Log but continue
        e.auditLogger.Log(ctx, AuditEntry{
            Timestamp: time.Now(),
            UserID:    session.UserID,
            Action:    "OLD_SESSION_REVOKE_FAILED",
            Status:    "WARNING",
            Error:     err.Error(),
        })
    }

    // Audit
    e.auditLogger.Log(ctx, AuditEntry{
        Timestamp: time.Now(),
        UserID:    session.UserID,
        Action:    ActionTokenRefresh,
        Status:    "SUCCESS",
    })

    return newTokens, nil
}

// generateTokens creates JWT access token and refresh token
func (e *Engine) generateTokens(ctx context.Context, userID string, deviceInfo *DeviceInfo, ipAddress string) (*TokenPair, error) {
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
            ID:        generateSecureID("tok"),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    accessToken, err := token.SignedString([]byte(e.config.JWTSecret))
    if err != nil {
        return nil, fmt.Errorf("failed to sign access token: %w", err)
    }

    // Generate refresh token
    tokenBytes := make([]byte, 32)
    if _, err := rand.Read(tokenBytes); err != nil {
        return nil, fmt.Errorf("failed to generate refresh token: %w", err)
    }
    plainToken := base64.RawURLEncoding.EncodeToString(tokenBytes)
    
    // Generate SHA256 lookup hash
    sha := sha256.Sum256([]byte(plainToken))
    lookupHash := hex.EncodeToString(sha[:])
    
    // Generate bcrypt storage hash
    storageHash, err := e.hasher.Hash(plainToken)
    if err != nil {
        return nil, fmt.Errorf("failed to hash refresh token: %w", err)
    }
    
    // Create session
    session, err := e.sessions.Create(ctx, userID, storageHash, lookupHash, deviceInfo, ipAddress)
    if err != nil {
        return nil, fmt.Errorf("failed to create session: %w", err)
    }
    
    // Verify the session was created with the lookup hash
    if session.LookupHash != lookupHash {
        return nil, fmt.Errorf("session lookup hash mismatch")
    }

    return &TokenPair{
        AccessToken:  accessToken,
        RefreshToken: plainToken,
        TokenType:    "Bearer",
        ExpiresIn:    int64(e.config.AccessTokenTTL.Seconds()),
    }, nil
}

// Authenticate extracts user ID from token
func (e *Engine) Authenticate(tokenString string) (string, error) {
    claims, err := e.VerifyToken(tokenString)
    if err != nil {
        return "", err
    }
    return claims.UserID, nil
}

// VerifyToken validates a JWT access token
func (e *Engine) VerifyToken(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(e.config.JWTSecret), nil
    })

    if err != nil {
        return nil, fmt.Errorf("failed to parse token: %w", err)
    }

    if claims, ok := token.Claims.(*Claims); ok && token.Valid {
        return claims, nil
    }
    return nil, ErrInvalidToken
}
