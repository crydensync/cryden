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
)
