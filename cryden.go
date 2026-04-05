// Package cryden is the main entry point for the CrydennSync authentication engine. 
package cryden

import (
        "context"
				"database/sql"
				"fmt"

        "github.com/crydensync/cryden/internal/core"
        "github.com/crydensync/cryden/internal/stores/memory"
        "github.com/crydensync/cryden/internal/stores/sqlite"
				"github.com/crydensync/cryden/internal/stores/mongodb"
				"github.com/crydensync/cryden/internal/stores/postgres"
)

// Engine is the main authentication engine.
type Engine = core.Engine

// New creates an in-memory engine (perfect for testing)
func New() *Engine {
        userStore := memory.NewUserStore()
        sessionStore := memory.NewSessionStore()
        return core.New(userStore, sessionStore)
}

// WithSQLite creates an engine with persistent SQLite storage
func WithSQLite(dbPath string) (*Engine, error) {
    // Create user store (which creates/migrates DB)
    userStore, err := sqlite.NewUserStore(dbPath)
    if err != nil {
        return nil, err
    }

    // Get the DB connection from user store
    // You'll need to add this method to UserStore
    type dbGetter interface {
        GetDB() *sql.DB
    }
    getter, ok := userStore.(dbGetter)
    if !ok {
        return nil, fmt.Errorf("user store does not expose DB connection")
    }
    db := getter.GetDB()

    // Create session store with same DB
    sessionStore := sqlite.NewSessionStore(db)

    return core.New(userStore, sessionStore), nil
}

// WithMongoDB creates an engine with MongoDB storage
func WithMongoDB(uri, dbName string) (*Engine, error) {
    userStore, err := mongodb.NewUserStore(uri, dbName)
    if err != nil {
        return nil, err
    }
    
    sessionStore, err := mongodb.NewSessionStore(uri, dbName)
    if err != nil {
        return nil, err
    }
    
    return core.New(userStore, sessionStore), nil
}

// WithPostgreSQL creates an engine with PostgreSQL storage
func WithPostgreSQL(connStr string) (*Engine, error) {
    userStore, err := postgres.NewUserStore(connStr)
    if err != nil {
        return nil, err
    }
    
    // Get the DB connection from user store to reuse
    db := userStore.GetDB() // You'll need to add this method
    
    sessionStore := postgres.NewSessionStore(db)
    
    return core.New(userStore, sessionStore), nil
}

// WithFileAuditLogger sets a file-based audit logger
func WithFileAuditLogger(engine *Engine, filePath string) (*Engine, error) {
    logger, err := core.NewFileAuditLogger(filePath)
    if err != nil {
        return nil, err
    }
    return engine.WithAuditLogger(logger), nil
}

// ==================== AUTHENTICATION FLOWS ====================

// SignUp creates a new user account
func SignUp(ctx context.Context, engine *Engine, email, password string) (*User, error) {
        return engine.SignUp(ctx, email, password)
}

// Login authenticates a user and returns tokens
func Login(ctx context.Context, engine *Engine, email, password string) (*TokenPair, *LimitResult, error) {
        return engine.Login(ctx, email, password)
}

// Logout revokes the current session
func Logout(ctx context.Context, engine *Engine, refreshToken string) error {
        return engine.Logout(ctx, refreshToken)
}

// LogoutAll revokes ALL sessions for a user
func LogoutAll(ctx context.Context, engine *Engine, userID string) error {
        return engine.LogoutAll(ctx, userID)
}

// ChangePassword updates user's password and logs out all devices
func ChangePassword(ctx context.Context, engine *Engine, userID, oldPassword, newPassword string) error {
        return engine.ChangePassword(ctx, userID, oldPassword, newPassword)
}

// ChangeEmail updates user's email
func ChangeEmail(ctx context.Context, engine *Engine, userID, newEmail string) error {
        return engine.ChangeEmail(ctx, userID, newEmail)
}

// DeleteAccount removes user and all sessions
func DeleteAccount(ctx context.Context, engine *Engine, userID string) error {
        return engine.DeleteAccount(ctx, userID)
}

// RefreshToken issues new tokens and rotates the refresh token
func RefreshToken(ctx context.Context, engine *Engine, refreshToken string) (*TokenPair, error) {
        return engine.RefreshToken(ctx, refreshToken)
}

// VerifyToken validates a JWT access token and returns the user ID
func VerifyToken(engine *Engine, tokenString string) (string, error) {
        claims, err := engine.VerifyToken(tokenString)
        if err != nil {
                return "", err
        }
        return claims.UserID, nil
}

// ==================== USER MANAGEMENT ====================

// GetUser retrieves a user by ID
func GetUser(ctx context.Context, engine *Engine, userID string) (*User, error) {
        return engine.GetUser(ctx, userID)
}

// GetUserByEmail retrieves a user by email
func GetUserByEmail(ctx context.Context, engine *Engine, email string) (*User, error) {
        return engine.GetUserByEmail(ctx, email)
}

// ==================== SESSION MANAGEMENT ====================

// ListSessions returns all active sessions for a user
func ListSessions(ctx context.Context, engine *Engine, userID string) ([]Session, error) {
        return engine.ListSessions(ctx, userID)
}

// RevokeSession manually revokes a specific session
func RevokeSession(ctx context.Context, engine *Engine, sessionID string) error {
        return engine.RevokeSession(ctx, sessionID)
}

// ==================== CONFIGURATION ====================

// WithJWTSecret sets a custom JWT secret
func WithJWTSecret(engine *Engine, secret string) *Engine {
        return engine.WithJWTSecret(secret)
}

// WithRateLimiter sets a custom rate limiter
func WithRateLimiter(engine *Engine, limiter RateLimiter) *Engine {
        return engine.WithRateLimiter(limiter)
}

// WithAuditLogger sets a custom audit logger
func WithAuditLogger(engine *Engine, logger AuditLogger) *Engine {
        return engine.WithAuditLogger(logger)
}

// WithHasher sets a custom password hasher
func WithHasher(engine *Engine, hasher Hasher) *Engine {
        return engine.WithHasher(hasher)
}

// ==================== RE-EXPORTED TYPES ====================

type User = core.User
type Session = core.Session
type TokenPair = core.TokenPair
type LimitResult = core.LimitResult
type Claims = core.Claims

// Interfaces
type UserStore = core.UserStore
type SessionStore = core.SessionStore
type Hasher = core.Hasher
type RateLimiter = core.RateLimiter
type AuditLogger = core.AuditLogger
type AuditEntry = core.AuditEntry

// ==================== RE-EXPORTED ERRORS ====================

var (
        ErrUserExists         = core.ErrUserExists
        ErrUserNotFound       = core.ErrUserNotFound
        ErrInvalidCredentials = core.ErrInvalidCredentials
        ErrInvalidEmail       = core.ErrInvalidEmail
        ErrPasswordTooShort   = core.ErrPasswordTooShort
        ErrPasswordTooLong    = core.ErrPasswordTooLong
        ErrPasswordNoUpper    = core.ErrPasswordNoUpper
        ErrPasswordNoLower    = core.ErrPasswordNoLower
        ErrPasswordNoNumber   = core.ErrPasswordNoNumber
        ErrTooManyAttempts    = core.ErrTooManyAttempts
        ErrInvalidToken       = core.ErrInvalidToken
        ErrSessionNotFound    = core.ErrSessionNotFound
)
