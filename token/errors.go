package token

import "errors"

var (
	ErrTokenByteLengthTooShort = errors.New("token: byte length below minimum safe entropy (16 bytes / 128 bits)")
	ErrMissingJWTSecret        = errors.New("token: JWT secret must not be empty")
	ErrInvalidTTL              = errors.New("token: TTL must be greater than zero")
)
