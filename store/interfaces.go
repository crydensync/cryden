package store

import (
	"context"
	"time"
)

// User is the domain representation of a user record.
// Storage implementations map their own row/document types to/from this.
type User struct {
	ID             string
	Email          string
	PasswordHash   string
	FailedAttempts int
	LockedUntil    *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// UserStore defines persistence operations for users.
type UserStore interface {
	Create(ctx context.Context, user User) error
	GetByEmail(ctx context.Context, email string) (User, error)
	GetByID(ctx context.Context, id string) (User, error)
	UpdateEmail(ctx context.Context, id string, newEmail string) error
	UpdatePasswordHash(ctx context.Context, id string, newHash string) error
	Delete(ctx context.Context, id string) error

	// IncrementFailedAttempts records one failed login and returns the
	// new total count, so callers can decide whether to lock the
	// account without a separate read.
	IncrementFailedAttempts(ctx context.Context, id string) (int, error)
	// ResetFailedAttempts clears the counter — called on successful login.
	ResetFailedAttempts(ctx context.Context, id string) error
	// LockAccount sets LockedUntil. Persistent (DB-backed), not
	// in-memory — must survive process restarts and work correctly
	// across multiple instances, unlike the rate limiter.
	LockAccount(ctx context.Context, id string, until time.Time) error
}

// Session is the domain representation of a refresh-token-backed session.
// TokenHash is the SHA-256 hash of the raw refresh token — the raw token
// is never persisted.
type Session struct {
	ID        string
	FamilyID  string
	UserID    string
	TokenHash string
	IP        string
	UserAgent string
	CreatedAt time.Time
	RevokedAt *time.Time
}

// SessionStore defines persistence operations for sessions and refresh
// token rotation chains. v1 ships one implementation:
// store/postgres.PostgresSessionStore.
type SessionStore interface {
	Create(ctx context.Context, s Session) error
	GetByID(ctx context.Context, sessionID string) (Session, error)
	GetByTokenHash(ctx context.Context, tokenHash string) (Session, error)
	ListByUser(ctx context.Context, userID string) ([]Session, error)
	Revoke(ctx context.Context, sessionID string) error
	RevokeFamily(ctx context.Context, familyID string) error
	RevokeAllForUser(ctx context.Context, userID string) error

	// RotateToken atomically revokes oldSessionID and creates newSession
	// in a single storage operation (a DB transaction in the Postgres
	// implementation). This prevents a crash between separate revoke
	// and create calls from leaving a session family in an inconsistent
	// state (old token dead, new token never created).
	RotateToken(ctx context.Context, oldSessionID string, newSession Session) error
}

// AuditEventType identifies the kind of audit event recorded.
type AuditEventType string

const (
	EventSignupSuccess        AuditEventType = "signup_success"
	EventLoginSuccess         AuditEventType = "login_success"
	EventLoginFailed          AuditEventType = "login_failed"
	EventLogout               AuditEventType = "logout"
	EventLogoutAll            AuditEventType = "logout_all"
	EventTokenRotated         AuditEventType = "token_rotated"
	EventTokenReuseDetected   AuditEventType = "token_reuse_detected"
	EventSessionRevoked       AuditEventType = "session_revoked"
	EventAccountLocked        AuditEventType = "account_locked"
	EventPasswordChanged      AuditEventType = "password_changed"
	EventEmailChangeRequested AuditEventType = "email_change_requested"
	EventEmailChanged         AuditEventType = "email_changed"
	EventAccountDeleted       AuditEventType = "account_deleted"
)

// AuditEvent is a single security-relevant, queryable record.
// Distinct from operational logging (see logger.Logger) — this is
// domain data written to the consuming app's own store.
type AuditEvent struct {
	ID        string
	Type      AuditEventType
	UserID    string
	IP        string
	Metadata  map[string]string
	CreatedAt time.Time
}

// AuditStore defines persistence for audit events.
// v1 ships one implementation: store/postgres.PostgresAuditStore.
type AuditStore interface {
	Record(ctx context.Context, event AuditEvent) error
	ListByUser(ctx context.Context, userID string, limit int) ([]AuditEvent, error)
}

// VerificationPurpose distinguishes what a verification token is for —
// a single table/store serves both signup email verification and
// email-change confirmation, since the lifecycle (issue, hash, expire,
// consume once) is identical.
type VerificationPurpose string

const (
	PurposeEmailVerify VerificationPurpose = "email_verify"
	PurposeEmailChange VerificationPurpose = "email_change"
)

// VerificationToken represents a single-use, expiring token sent to an
// email address. NewEmail is only set for PurposeEmailChange — it's
// the address the user is trying to change TO, not their current one.
type VerificationToken struct {
	ID        string
	UserID    string
	Purpose   VerificationPurpose
	TokenHash string
	NewEmail  string // only used for PurposeEmailChange
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// VerificationStore defines persistence for verification tokens.
type VerificationStore interface {
	Create(ctx context.Context, vt VerificationToken) error
	GetByTokenHash(ctx context.Context, tokenHash string) (VerificationToken, error)
	MarkUsed(ctx context.Context, id string) error
}
