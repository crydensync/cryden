package cryden

import (
	"github.com/crydensync/cryden/internal/core"
	"github.com/crydensync/cryden/internal/stores/memory"
	"github.com/crydensync/cryden/internal/stores/sqlite"
)

// Engine is the main authentication engine
type Engine = core.Engine

// New creates an in-memory engine (perfect for testing)
func New() *Engine {
	userStore := memory.NewUserStore()
	sessionStore := memory.NewSessionStore()
	return core.New(userStore, sessionStore)
}

// WithSQLite creates an engine with persistent SQLite storage
func WithSQLite(dbPath string) (*Engine, error) {
	userStore, err := sqlite.NewUserStore(dbPath)
	if err != nil {
		return nil, err
	}
	// For now, we need to expose DB() method - we'll fix this later
	sessionStore := memory.NewSessionStore() // Temporary
	return core.New(userStore, sessionStore), nil
}

type User = core.User
type Session = core.Session
type TokenPair = core.TokenPair
type LimitResult = core.LimitResult

var (
	ErrUserExists         = core.ErrUserExists
	ErrUserNotFound       = core.ErrUserNotFound
	ErrInvalidCredentials = core.ErrInvalidCredentials
	ErrInvalidEmail       = core.ErrInvalidEmail
	ErrPasswordTooShort   = core.ErrPasswordTooShort
	ErrTooManyAttempts    = core.ErrTooManyAttempts
	ErrInvalidToken       = core.ErrInvalidToken
)
