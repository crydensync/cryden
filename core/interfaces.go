package core

import "context"

// UserStore defines how we store and retrieve users
// ANY database can implement this interface 
type UserStore interface {
	Create(ctx context.Context, email, passwordHash string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByID(ctx context.Context, id string) (*User, error)
	UpdateEmail(ctx context.Context, id, newEmail string) error 
	UpdatePassword(ctx context.Context, id, newPasswordHash string) error
	Delete(ctx context.Context, id string) error
}

// SessionStore defines how we store retrieve sessions
type SessionStore interface {
	Create(ctx context.Context, userID string) (*Session,  error)
	GetByRefreshToken(ctx context.Context, refreshToken string) (*Session, error)
	Revoke(ctx context.Context, sessionID string) error
	RevokeAllForUser(ctx context.Context, userID string) error
	ListForUser(ctx context.Context, userID string) ([]Session, error)
}
