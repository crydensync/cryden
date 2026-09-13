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
	EventPasswordBreachRejected  AuditEventType = "password_breach_rejected"

	// EventAnomalyDetected records that a login attempt tripped one or
	// more anomaly signals (see security.AnomalySignal). Metadata
	// carries a "signals" key listing which ones fired, plus the counts
	// behind them. Recorded on an otherwise SUCCESSFUL primary
	// authentication — it annotates a login that was allowed to
	// proceed, it is never a rejection, and there is deliberately no
	// matching sentinel error for callers to branch on.
	EventAnomalyDetected AuditEventType = "anomaly_detected"

	// EventCredentialStuffingDetected records that one IP's recent failed
	// attempts were spread across enough different target accounts to
	// look like credential stuffing rather than a forgotten password.
	// Metadata carries the same "signals" key as EventAnomalyDetected
	// plus the breadth counts behind it.
	//
	// Its own type, not more EventAnomalyDetected metadata, because the
	// two answer different questions: an anomaly event is about one
	// account and belongs in that user's history, while this one is about
	// an IP attacking many accounts and is usually queried system-wide
	// (see AuditStore.SearchByType). UserID is whichever account the
	// triggering attempt named, and is empty when that attempt named an
	// email with no account behind it — it is incidental context, never
	// the subject of the event.
	//
	// Recorded on failed AND successful attempts, and never a rejection:
	// a success arriving from an IP that is spraying is the single most
	// important case to surface, since it means one of the guesses landed.
	EventCredentialStuffingDetected AuditEventType = "credential_stuffing_detected"

	// EventPasswordHashUpgraded records that a successful login found the
	// account's stored password hash out of date — a weaker algorithm, or
	// the configured one at costs since raised — and rewrote it. Metadata
	// carries "from" and "to" algorithm names (see
	// security.IdentifyHash); neither the password nor either hash is
	// ever recorded.
	//
	// It exists because a hash migration is otherwise invisible: this is
	// how an operator watches one drain, by counting these against the
	// user total (see AuditStore.SearchByType). Recorded only on a login
	// that already succeeded, and never a rejection — a failed rewrite
	// leaves the old hash in place and the login stands.
	EventPasswordHashUpgraded AuditEventType = "password_hash_upgraded"

	// EventAPIKeyCreated records that a new machine-to-machine key was
	// issued for an account. Metadata carries "key_id", "prefix" and the
	// "scopes" it was granted — never the key itself, which exists only
	// in the value returned to whoever asked for it.
	EventAPIKeyCreated AuditEventType = "api_key_created"

	// EventAPIKeyRevoked records that a key was revoked. Metadata carries
	// "key_id". A revoked key is dead from the next request onward; there
	// is no un-revoke, and generating a replacement is a separate event.
	EventAPIKeyRevoked AuditEventType = "api_key_revoked"

	// EventAPIKeyRejected records that a REAL key was presented and
	// refused — revoked, or past its expiry. Metadata carries "key_id"
	// and a "reason" of "revoked" or "expired".
	//
	// Deliberately not recorded for an unrecognised key, which is the
	// case that looks most like an attack and is the only one an attacker
	// controls: anybody can post arbitrary bytes as a key, and auditing
	// those would hand the internet a write endpoint into this table.
	// What is left is the signal worth having and impossible to
	// manufacture — a key that this system really issued, still in use
	// after it was retired, which means either a deployment nobody
	// updated or somebody holding a credential they should not have.
	//
	// Successful authentications are not recorded either, for the
	// throughput reason rather than the security one: one audit row per
	// machine request would make the audit table the busiest table in the
	// database and bury every event a human wanted to read.
	EventAPIKeyRejected AuditEventType = "api_key_rejected"
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

// LoginAttemptOutcome records whether one observed primary
// authentication attempt succeeded. Only these two values exist — an
// attempt that never got as far as checking a credential (rate limited,
// account already locked) is not an observation about the credential
// and is deliberately not recorded here.
type LoginAttemptOutcome string

const (
	OutcomeSuccess LoginAttemptOutcome = "success"
	OutcomeFailure LoginAttemptOutcome = "failure"
)

// LoginAttempt is one observed primary-authentication attempt, stored
// so anomaly detection can answer questions about a user's normal
// behavior cheaply. It overlaps in spirit with AuditEvent — both are
// append-only security history — but not in shape or access pattern:
// audit history is read as a chronological list for a human, while
// these rows are only ever read as aggregates over a time window and
// indexed for exactly that (see AnomalyStore). Deriving the same
// answers from AuditStore would mean scanning and filtering audit
// history on every single login.
//
// UserID is empty when the attempt named an email that resolves to no
// account — an unknown-email failure is still real evidence about the
// IP, which is the whole point of tracking it.
type LoginAttempt struct {
	ID        string
	UserID    string
	IP        string
	UserAgent string
	Outcome   LoginAttemptOutcome
	CreatedAt time.Time
}

// AnomalyStore defines persistence for login-attempt observations. It
// exists as its own store rather than as more AuditStore queries so
// each read below can be a single indexed lookup, and rather than as
// part of the in-memory rate limiter because that one is explicitly
// documented as incorrect across multiple instances — a detector whose
// history resets on deploy, or differs per process, would flag normal
// behavior and miss real attacks.
//
// Every method is read-mostly and best-effort by contract: a caller
// that fails to record or read an observation logs it and continues.
// Detection is an annotation on a login, never a gate, so a broken
// AnomalyStore must never be able to stop a legitimate user logging in.
type AnomalyStore interface {
	// RecordAttempt appends one observation. Implementations assign
	// CreatedAt (and ID) themselves — the caller does not supply a
	// clock, matching AuditStore.Record.
	RecordAttempt(ctx context.Context, attempt LoginAttempt) error

	// ListRecentSuccesses returns up to limit of the user's most recent
	// SUCCESSFUL attempts, newest first — the known-IP/known-device
	// baseline. Successes only: a failed attempt must never be able to
	// teach the baseline that an IP is familiar.
	ListRecentSuccesses(ctx context.Context, userID string, limit int) ([]LoginAttempt, error)

	// CountFailuresForUser counts this user's failed attempts at or
	// after since.
	CountFailuresForUser(ctx context.Context, userID string, since time.Time) (int, error)

	// CountFailuresForIP counts failed attempts from this IP at or
	// after since, across every account it targeted — including
	// attempts against emails that match no account.
	CountFailuresForIP(ctx context.Context, ip string, since time.Time) (int, error)

	// CountTargetsForIP reports how broadly this IP's failures at or
	// after since were spread, rather than how many there were —
	// credential stuffing is one password against many accounts, which
	// CountFailuresForIP's total cannot distinguish from one account
	// being hammered.
	//
	// Reads the same rows and the same partial index
	// (idx_login_attempts_ip_failures) as CountFailuresForIP; no
	// additional table or migration exists for this.
	CountTargetsForIP(ctx context.Context, ip string, since time.Time) (IPTargetCounts, error)
}

// IPTargetCounts is the result of AnomalyStore.CountTargetsForIP: how
// many different targets one IP's recent failures were aimed at, split
// by whether the target exists. Two numbers instead of one total
// because they are counted differently and mean different things — see
// security.CredentialStuffingObservations, whose fields these map onto.
type IPTargetCounts struct {
	// DistinctAccounts is the number of DIFFERENT existing accounts the
	// IP failed against (COUNT(DISTINCT user_id) in SQL terms, which
	// excludes the NULL rows counted below).
	DistinctAccounts int

	// UnknownTargetFailures is the number of failures from that IP whose
	// target resolved to no account, i.e. rows with a NULL user_id. A
	// count of attempts, not of distinct email addresses: the attempted
	// address is deliberately not stored, so the same nonexistent email
	// probed twice counts twice.
	UnknownTargetFailures int
}

// APIKey is one machine-to-machine credential belonging to a user. It
// is a second, parallel way to authenticate as that user — no password,
// no session, no refresh token, and deliberately outside the
// second-factor system entirely: there is no human at the other end to
// prompt for a code, so a key that resolved would then pause forever.
//
// KeyHash is the SHA-256 hash of the raw key (token.HashToken), the
// same fast hash refresh tokens and recovery codes use, for the same
// reason plus one more. The reason they share: the raw value is
// crypto/rand output, not a human-chosen secret, so there is no
// weak-guessing risk a slow hash would defend against. The one they
// don't: a password is verified once per login, while a key is verified
// on every single request a machine makes, so bcrypt's cost would be
// paid per call, forever, on the hottest path in the engine.
//
// The raw key exists exactly once, in the value auth.GenerateAPIKey
// returns. Nothing here can reproduce it.
type APIKey struct {
	ID     string
	UserID string
	// Name is a host-supplied label ("CI deploy bot") shown when
	// listing keys — presentational, like WebAuthnCredential.Nickname,
	// never used for a security decision, and not required to be
	// unique or non-empty.
	Name string
	// Prefix is the leading, non-secret fragment of the raw key
	// ("ck_a1b2c3d4"), stored in the clear so a management UI, and the
	// host's own logs, can say which key is which without holding the
	// key itself. Not a lookup key, not unique by construction — the
	// stored secret is KeyHash and only KeyHash.
	Prefix  string
	KeyHash string
	// Scopes are host-defined permission strings, stored and returned
	// verbatim. The engine never interprets one — same reasoning as
	// OAuthIdentity.Provider being a plain string rather than an enum:
	// a new scope must never require an engine change. Enforcing them
	// is the host's job, and auth.APIKeyIdentity.HasScope is the only
	// help offered.
	Scopes []string
	// ExpiresAt is nil for a key that never expires, which is the
	// default. Expiry is enforced by auth.AuthenticateAPIKey rather
	// than by the store: GetByKeyHash returns expired and revoked rows
	// so that layer can tell them apart from a key that never existed,
	// which is a distinction the audit trail depends on.
	ExpiresAt *time.Time
	CreatedAt time.Time
	// LastUsedAt is the operational signal that answers "is anything
	// still using this key?" before someone deletes it. Updated coarsely
	// on purpose (see auth.AuthenticateAPIKey) — treat it as accurate to
	// within a few minutes, never as a per-request access log.
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// APIKeyStore defines persistence for API keys.
//
// Every method here is on a request path, not an administrative one:
// GetByKeyHash in particular runs once per authenticated machine
// request, which is why it is a single lookup on a unique index and why
// nothing in this interface returns a joined or aggregated shape.
type APIKeyStore interface {
	// Create inserts the key. A zero CreatedAt means the store assigns
	// it; a set one is stored as given, so that one clock decides both
	// it and ExpiresAt — the caller derives the expiry from its own
	// now(), and a store stamping only the other half is how a row ends
	// up claiming it expired before it was created.
	Create(ctx context.Context, key APIKey) error

	// GetByKeyHash returns the key with this hash whatever its state —
	// revoked and expired rows come back like any other. Filtering
	// those is auth.AuthenticateAPIKey's job, because the difference
	// between "no such key" and "a real key that is no longer usable"
	// is the difference between silence and an audit event.
	GetByKeyHash(ctx context.Context, keyHash string) (APIKey, error)

	// ListByUser returns the user's keys newest-first, excluding
	// revoked ones — the same active-only convention as
	// SessionStore.ListByUser. Expired-but-unrevoked keys ARE included:
	// "your CI key expired on Tuesday" is exactly what someone needs to
	// see to understand why a pipeline broke, whereas a revoked key has
	// already been dealt with.
	ListByUser(ctx context.Context, userID string) ([]APIKey, error)

	// Revoke marks keyID revoked, scoped to userID. Ownership is
	// enforced in the statement rather than by reading the row and
	// comparing in Go: one round trip does both, and a caller can never
	// learn whether somebody else's key exists. Returns ErrNotFound for
	// a key that does not exist, is already revoked, or belongs to
	// another user — all three indistinguishable on purpose.
	Revoke(ctx context.Context, userID, keyID string) error

	// TouchLastUsed records that keyID was just used. The clock is the
	// caller's, unlike AuditStore.Record and AnomalyStore.RecordAttempt
	// which assign their own, because the caller only calls this when
	// the value it already read is stale enough to be worth a write and
	// must store the same instant it compared against.
	//
	// Best-effort by contract: a zero-row update is not an error (the
	// key may have been revoked a moment ago), and the caller treats a
	// real failure as a log line, never as a failed request.
	TouchLastUsed(ctx context.Context, keyID string, at time.Time) error
}
