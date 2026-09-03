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
)
