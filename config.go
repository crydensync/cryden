package cryden

import (
	"time"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/notify"
	"github.com/crydensync/cryden/v2/store"
)

// Config wires an Engine. Stores are injected directly, not
// constructed internally — the engine never hardcodes a storage
// backend. To run against Postgres, construct
// store/postgres.PostgresUserStore etc. and assign them here; for
// tests, use store/memory equivalents.
type Config struct {
	// Required — no default exists for any of these.
	JWTSecret string
	Users     store.UserStore
	Sessions  store.SessionStore
	Audit     store.AuditStore

	// Optional — only needed if you use RequestEmailChange /
	// ConfirmEmailChange. Leave nil if you don't need that flow;
	// calling it without these configured returns a clear error
	// rather than a nil-pointer panic.
	Verifications store.VerificationStore
	EmailSender   notify.EmailSender
	// OAuth is optional — only required if LoginWithOAuth is used.
	// Left unset, LoginWithOAuth returns ErrOAuthNotConfigured.
	OAuth store.OAuthStore
	// TOTP is optional — only required if EnrollTOTP / ConfirmTOTP /
	// DisableTOTP / CompleteLoginWithTOTP are used. Left unset, those
	// facade functions return ErrTOTPNotConfigured and Login never
	// checks for a second factor. If set, EncryptionKey must also be
	// set (validated below) — a TOTP secret is encrypted, not hashed,
	// since the engine must recover it in plaintext to check codes.
	TOTP store.TOTPStore
	// EncryptionKey encrypts TOTP secrets at rest. Required only if
	// TOTP is set. Like JWTSecret, this should be a long, random
	// value kept out of source control — it is hashed internally to
	// derive an AES-256 key, but that normalizes length only, it does
	// not substitute for the input itself being high-entropy.
	EncryptionKey string
	// TOTPIssuerName is shown inside the user's authenticator app
	// next to their account (e.g. "MyApp (user@example.com)").
	// Optional — defaults to "Cryden" if TOTP is set and this is left
	// blank, but you almost certainly want to override it with your
	// own app's name.
	TOTPIssuerName string

	// Optional — sensible defaults applied in New() if zero-valued.
	// These are tuning knobs, not security-critical secrets, so
	// defaulting them (unlike JWTSecret) is safe.
	AccessTokenTTL         time.Duration // default: 15 minutes
	BcryptCost             int           // default: bcrypt.DefaultCost (10)
	RefreshTokenByteLength int           // default: 32
	RateLimitAttempts      int           // default: 10
	RateLimitWindow        time.Duration // default: 1 minute
	LockoutThreshold       int           // default: 5 failed attempts
	LockoutDuration        time.Duration // default: 15 minutes
	Logger                 logger.Logger // default: ConsoleJSONLogger
}

func (c *Config) validate() error {
	if c.JWTSecret == "" {
		return ErrMissingJWTSecret
	}
	if c.Users == nil {
		return ErrMissingUserStore
	}
	if c.Sessions == nil {
		return ErrMissingSessionStore
	}
	if c.Audit == nil {
		return ErrMissingAuditStore
	}
	if c.TOTP != nil && c.EncryptionKey == "" {
		return ErrMissingEncryptionKey
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.AccessTokenTTL == 0 {
		c.AccessTokenTTL = 15 * time.Minute
	}
	if c.BcryptCost == 0 {
		c.BcryptCost = 10
	}
	if c.RefreshTokenByteLength == 0 {
		c.RefreshTokenByteLength = 32
	}
	if c.RateLimitAttempts == 0 {
		c.RateLimitAttempts = 10
	}
	if c.RateLimitWindow == 0 {
		c.RateLimitWindow = time.Minute
	}
	if c.LockoutThreshold == 0 {
		c.LockoutThreshold = 5
	}
	if c.LockoutDuration == 0 {
		c.LockoutDuration = 15 * time.Minute
	}
	if c.TOTP != nil && c.TOTPIssuerName == "" {
		c.TOTPIssuerName = "Cryden"
	}
	if c.Logger == nil {
		c.Logger = logger.NewConsoleJSONLogger()
	}
}
