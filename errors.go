package cryden

import "errors"

var (
	ErrMissingJWTSecret    = errors.New("cryden: JWTSecret is required")
	ErrMissingUserStore    = errors.New("cryden: Config.Users is required")
	ErrMissingSessionStore = errors.New("cryden: Config.Sessions is required")
	ErrMissingAuditStore   = errors.New("cryden: Config.Audit is required")
)
