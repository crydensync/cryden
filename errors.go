package cryden

import "errors"

var (
	ErrMissingJWTSecret    = errors.New("cryden: JWTSecret is required")
	ErrMissingUserStore    = errors.New("cryden: Config.Users is required")
	ErrMissingSessionStore = errors.New("cryden: Config.Sessions is required")
	ErrMissingAuditStore   = errors.New("cryden: Config.Audit is required")
	// ErrMissingEncryptionKey is returned by New if Config.TOTP is set
	// but Config.EncryptionKey isn't — a TOTP secret must be
	// decryptable to validate codes against it, so it can't fall back
	// to hashing (as passwords/tokens do) the way other secrets can.
	ErrMissingEncryptionKey = errors.New("cryden: EncryptionKey is required when Config.TOTP is set")
	// ErrMissingWebAuthnConfig is returned by New if Config.WebAuthn
	// is set but WebAuthnRPID, WebAuthnRPDisplayName, or
	// WebAuthnRPOrigins isn't — all three are required together, none
	// has a safe default (RPID especially: guessing wrong binds every
	// registered passkey to the wrong domain).
	ErrMissingWebAuthnConfig = errors.New("cryden: WebAuthnRPID, WebAuthnRPDisplayName, and WebAuthnRPOrigins are all required when Config.WebAuthn is set")
	// ErrMissingVerificationStore is returned by New if
	// Config.MagicLinkSender is set but Config.Verifications isn't —
	// magic-link tokens are stored there, alongside email-change
	// tokens, distinguished by purpose.
	ErrMissingVerificationStore = errors.New("cryden: Config.Verifications is required when Config.MagicLinkSender is set")
	// ErrInvalidAPIKeyPrefix is returned by New if
	// Config.APIKeyPrefix contains whitespace or an underscore. The
	// underscore is the separator between the label and the secret in a
	// generated key, and whitespace in a credential that travels in an
	// Authorization header is a support ticket waiting to happen.
	ErrInvalidAPIKeyPrefix = errors.New("cryden: Config.APIKeyPrefix must not contain whitespace or an underscore")
)
