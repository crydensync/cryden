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

	// ListAll returns users newest-first, paginated. Added to close a
	// real gap: earlier tooling (the admin CLI) needed this and had no
	// way to get it except querying the schema directly. Read-only,
	// no ownership semantics to enforce, safe as a store-level method.
	ListAll(ctx context.Context, limit, offset int) ([]User, error)
	// Count returns the total number of users.
	Count(ctx context.Context) (int, error)
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

	// CountActive returns the total number of active (non-revoked)
	// sessions, system-wide — not scoped to one user. Closes a real
	// gap: admin tooling needed this and had no non-store-bypassing way
	// to get it.
	CountActive(ctx context.Context) (int, error)
}

// PublicSession is a redacted view of Session, safe to return to a
// client over an API — deliberately excludes TokenHash and FamilyID.
// Added because both known consuming apps (a reference HTTP API and a
// reference frontend app) independently wrote the same stripping
// logic themselves; this gives future consumers a ready option
// instead of a third reimplementation.
type PublicSession struct {
	ID        string
	IP        string
	UserAgent string
	CreatedAt time.Time
}

func (s Session) ToPublic() PublicSession {
	return PublicSession{ID: s.ID, IP: s.IP, UserAgent: s.UserAgent, CreatedAt: s.CreatedAt}
}

type AuditEventType string

const (
	EventSignupSuccess           AuditEventType = "signup_success"
	EventLoginSuccess            AuditEventType = "login_success"
	EventLoginFailed             AuditEventType = "login_failed"
	EventLogout                  AuditEventType = "logout"
	EventLogoutAll               AuditEventType = "logout_all"
	EventTokenRotated            AuditEventType = "token_rotated"
	EventTokenReuseDetected      AuditEventType = "token_reuse_detected"
	EventSessionRevoked          AuditEventType = "session_revoked"
	EventAccountLocked           AuditEventType = "account_locked"
	EventPasswordChanged         AuditEventType = "password_changed"
	EventEmailChangeRequested    AuditEventType = "email_change_requested"
	EventEmailChanged            AuditEventType = "email_changed"
	EventAccountDeleted          AuditEventType = "account_deleted"
	EventOAuthLinked             AuditEventType = "oauth_linked"
	EventTOTPEnabled             AuditEventType = "totp_enabled"
	EventTOTPDisabled            AuditEventType = "totp_disabled"
	EventTOTPChallengeFailed     AuditEventType = "totp_challenge_failed"
	EventWebAuthnRegistered      AuditEventType = "webauthn_registered"
	EventWebAuthnRemoved         AuditEventType = "webauthn_removed"
	EventWebAuthnChallengeFailed AuditEventType = "webauthn_challenge_failed"
	EventMagicLinkRequested      AuditEventType = "magic_link_requested"
	EventRecoveryCodesGenerated  AuditEventType = "recovery_codes_generated"
	EventRecoveryCodeUsed        AuditEventType = "recovery_code_used"
	EventRecoveryCodeFailed      AuditEventType = "recovery_code_failed"
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

	// SearchByType returns the most recent events of a given type,
	// across ALL users — ListByUser only supports per-user queries.
	// Closes a real gap found while building admin tooling: there was
	// no way to search for a security-relevant event system-wide
	// (e.g. "every token_reuse_detected event, whoever it happened to")
	// without bypassing the store layer entirely.
	SearchByType(ctx context.Context, eventType AuditEventType, limit int) ([]AuditEvent, error)
}

// VerificationPurpose distinguishes what a verification token is for —
// a single table/store serves both signup email verification and
// email-change confirmation, since the lifecycle (issue, hash, expire,
// consume once) is identical.
type VerificationPurpose string

const (
	PurposeEmailVerify VerificationPurpose = "email_verify"
	PurposeEmailChange VerificationPurpose = "email_change"
	// PurposeMagicLink marks a token as a passwordless login link — a
	// separate purpose from PurposeEmailVerify even though both are
	// "click a link in your email": GetByTokenHash's Purpose check is
	// what stops a leaked/guessed email-verification link from ever
	// being replayed as a login link, or vice versa.
	PurposeMagicLink VerificationPurpose = "magic_link"
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

// OAuthIdentity links a User to an external OAuth provider account.
// Provider is a plain string ("google", "github") rather than an enum
// so a new provider never requires an engine change. ExternalID is
// the provider's own stable user ID — never the email, since a
// provider's email on file can change and isn't a guaranteed stable
// identifier the way their internal ID is.
type OAuthIdentity struct {
	ID         string
	UserID     string
	Provider   string
	ExternalID string
	Email      string
	CreatedAt  time.Time
}

// OAuthStore defines persistence for linked OAuth identities.
type OAuthStore interface {
	Link(ctx context.Context, identity OAuthIdentity) error
	GetByProviderID(ctx context.Context, provider, externalID string) (OAuthIdentity, error)
	ListByUser(ctx context.Context, userID string) ([]OAuthIdentity, error)
	Unlink(ctx context.Context, identityID string) error
}

// TOTPSecret represents a user's enrolled TOTP (2FA) secret.
// EncryptedSecret is encrypted at rest via security.Encryptor — never
// hashed, since validating a code requires recovering the original
// secret, unlike passwords/tokens. ConfirmedAt is nil until the user
// proves possession with one valid code; an unconfirmed secret must
// never gate a login (see auth.ConfirmTOTP).
type TOTPSecret struct {
	UserID          string
	EncryptedSecret string
	ConfirmedAt     *time.Time
	CreatedAt       time.Time
}

// TOTPStore defines persistence for TOTP secrets. One secret per
// user — re-enrolling replaces the existing row rather than creating
// a second one, and always resets ConfirmedAt to nil, so restarting
// enrollment can never leave a stale confirmed secret active
// alongside a new unconfirmed one.
type TOTPStore interface {
	Upsert(ctx context.Context, secret TOTPSecret) error
	GetByUserID(ctx context.Context, userID string) (TOTPSecret, error)
	// Confirm marks the existing secret confirmed. Errors with
	// ErrNotFound if no secret is pending for userID.
	Confirm(ctx context.Context, userID string) error
	Delete(ctx context.Context, userID string) error
}

// WebAuthnCredential represents one registered passkey. Unlike
// TOTPSecret (one per user), a user can have several — one per
// device/authenticator. CredentialData is the JSON-marshaled form of
// the underlying webauthn.Credential library struct, stored as a
// blob rather than decomposed into columns — that struct gains new
// fields as the library evolves, and a blob avoids the storage layer
// drifting out of sync with it. CredentialID is denormalized out of
// that blob purely so it can be indexed/queried directly (matching a
// credential during login, excluding it during re-registration)
// without deserializing every row first.
type WebAuthnCredential struct {
	ID             string
	UserID         string
	CredentialID   []byte
	CredentialData []byte
	// Nickname is a user-supplied label ("MacBook Touch ID") shown
	// when listing passkeys — purely presentational, never used for
	// any security decision.
	Nickname   string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// WebAuthnCredentialStore defines persistence for passkeys.
type WebAuthnCredentialStore interface {
	Add(ctx context.Context, cred WebAuthnCredential) error
	ListByUser(ctx context.Context, userID string) ([]WebAuthnCredential, error)
	// Update overwrites CredentialData and LastUsedAt for the row
	// matching CredentialID — called after a successful login to
	// persist the authenticator's updated signature counter (cloned-
	// authenticator detection depends on this actually advancing).
	Update(ctx context.Context, cred WebAuthnCredential) error
	Delete(ctx context.Context, userID string, credentialID []byte) error
}

// RecoveryCode is one single-use fallback code for accounts with a
// second factor enrolled. CodeHash uses the same fast SHA-256 hash as
// refresh tokens (token.HashToken) rather than bcrypt — a recovery
// code is a high-entropy random value, not a user-chosen secret, so
// there's no weak-guessing risk a slow hash would defend against; the
// only way to find one is to already have it.
type RecoveryCode struct {
	UserID    string
	CodeHash  string
	UsedAt    *time.Time
	CreatedAt time.Time
}

// RecoveryCodeStore defines persistence for a user's batch of
// recovery codes.
type RecoveryCodeStore interface {
	// ReplaceAll wipes any existing codes for userID and inserts
	// codes as the new complete batch — generating a fresh set always
	// invalidates every previous one, there's no way to add codes to
	// an existing batch incrementally.
	ReplaceAll(ctx context.Context, userID string, codes []RecoveryCode) error
	// CountUnused is used to decide whether "recovery_code" belongs
	// in Login's Methods list — cheaper than fetching and hashing
	// every code just to check whether any remain.
	CountUnused(ctx context.Context, userID string) (int, error)
	// Consume finds an unused code matching codeHash for userID and
	// marks it used, atomically — the same code must never validate
	// twice. Returns ErrNotFound if no matching unused code exists
	// (wrong code, already used, or none generated at all).
	Consume(ctx context.Context, userID string, codeHash string) error
	// DeleteAll removes every code for userID. Not wired into
	// DisableTOTP/DeletePasskey automatically — recovery codes are
	// harmless to leave in place even with no second factor active,
	// since completePrimaryAuth only ever checks for unused recovery
	// codes when the account also has a confirmed TOTP secret or a
	// registered passkey (see completePrimaryAuth) — they can never
	// stand in as a login gate on their own. DeleteAll exists for
	// hygiene, if a host app wants to clean up explicitly.
	DeleteAll(ctx context.Context, userID string) error
}
