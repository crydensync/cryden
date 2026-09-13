package cryden

import (
	"time"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/notify"
	"github.com/crydensync/cryden/v2/security"
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
	// MagicLinkSender is optional — only required if RequestMagicLink
	// is used. Requires Verifications to also be set (magic-link
	// tokens reuse the same VerificationStore email-change/verify
	// tokens use, distinguished by store.PurposeMagicLink).
	MagicLinkSender notify.MagicLinkSender
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
	// WebAuthn is optional — only required if BeginRegisterPasskey /
	// FinishRegisterPasskey / ListPasskeys / DeletePasskey /
	// BeginWebAuthnLogin / CompleteLoginWithWebAuthn are used. Left
	// unset, those facade functions return ErrWebAuthnNotConfigured
	// and Login never checks for a passkey. If set, EncryptionKey,
	// WebAuthnRPID, WebAuthnRPDisplayName, and WebAuthnRPOrigins must
	// all also be set (validated below).
	WebAuthn store.WebAuthnCredentialStore
	// WebAuthnRPID is your app's real domain (e.g. "yourapp.com") —
	// unlike TOTPIssuerName, this is a genuine security parameter, not
	// cosmetic: passkeys are cryptographically bound to it, and a
	// credential registered against one RPID will never validate
	// against another.
	WebAuthnRPID string
	// WebAuthnRPDisplayName is shown to the user during the browser's
	// passkey prompt (e.g. "Your App Inc").
	WebAuthnRPDisplayName string
	// WebAuthnRPOrigins are the exact origins (scheme + host [+ port])
	// browsers are allowed to present credentials from, e.g.
	// []string{"https://yourapp.com"}. Must match what the browser
	// actually sends — a mismatch here is a common integration error,
	// not a security relaxation to work around casually.
	WebAuthnRPOrigins []string
	// RecoveryCodes is optional — only required if
	// GenerateRecoveryCodes / CompleteLoginWithRecoveryCode are used.
	// Left unset, those facade functions return
	// ErrRecoveryCodesNotConfigured and Login never advertises
	// "recovery_code" as an available second-factor method.
	RecoveryCodes store.RecoveryCodeStore
	// PasswordPolicy is checked on every SignUp/ChangePassword. Unlike
	// TOTP/WebAuthn, this has no "unconfigured means off" state —
	// leaving it as the entire zero value (security.PasswordPolicy{})
	// applies security.DefaultPasswordPolicy instead. Setting even one
	// field (e.g. just MinLength) counts as a real custom policy and
	// is used as-is — only the untouched, all-zero struct triggers the
	// default.
	PasswordPolicy security.PasswordPolicy
	// BreachedPasswordChecker is optional — only checked if set, on
	// SignUp/ChangePassword. Ships no implementation (see the type's
	// own doc comment); a checker error fails open rather than
	// blocking the account action.
	BreachedPasswordChecker security.BreachedPasswordChecker

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
	if c.WebAuthn != nil {
		if c.EncryptionKey == "" {
			return ErrMissingEncryptionKey
		}
		if c.WebAuthnRPID == "" || c.WebAuthnRPDisplayName == "" || len(c.WebAuthnRPOrigins) == 0 {
			return ErrMissingWebAuthnConfig
		}
	}
	if c.MagicLinkSender != nil && c.Verifications == nil {
		return ErrMissingVerificationStore
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
	// A single field being zero (e.g. MaxLength left unset while
	// MinLength/character requirements ARE set) is a real partial
	// policy, not an unconfigured one — comparing the whole struct
	// against its zero value is the only check that doesn't clobber a
	// custom policy just because one field was left at its default.
	if c.PasswordPolicy == (security.PasswordPolicy{}) {
		c.PasswordPolicy = security.DefaultPasswordPolicy
	}
	if c.Logger == nil {
		c.Logger = logger.NewConsoleJSONLogger()
	}
}
