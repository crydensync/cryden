package token

import "errors"

var (
	ErrTokenByteLengthTooShort = errors.New("token: byte length below minimum safe entropy (16 bytes / 128 bits)")
	ErrMissingJWTSecret        = errors.New("token: JWT secret must not be empty")
	ErrInvalidTTL              = errors.New("token: TTL must be greater than zero")

	// Reported by JWTIssuer when a ClaimsProvider returns something it is
	// not allowed to. Both fail the whole token rather than dropping the
	// offending claim: a provider returning "sub" is a bug in the host's
	// code every time, and a token issued anyway would be one whose
	// claims are half of what the host believes they are.
	ErrReservedClaim  = errors.New("token: claims provider returned a reserved claim name")
	ErrEmptyClaimName = errors.New("token: claims provider returned a claim with an empty name")
)
