package auth

import "errors"

var (
	ErrUserExists = errors.New("auth: user with this email already exists")
	// ErrInvalidCredentials is returned for both "no such user" and
	// "wrong password" — never differentiate in the returned error,
	// only in the audit log's metadata. Differentiating in the error
	// itself would let an attacker enumerate valid emails.
	ErrInvalidCredentials = errors.New("auth: invalid email or password")
	ErrRateLimited        = errors.New("auth: rate limit exceeded")
	// ErrAccountLocked is returned when an account has too many recent
	// failed login attempts. Distinct from ErrInvalidCredentials so
	// callers/UIs can show a different message — but note this DOES
	// leak that the account exists (unlike ErrInvalidCredentials).
	// That's an accepted tradeoff of lockout messaging in general.
	ErrAccountLocked = errors.New("auth: account temporarily locked due to failed login attempts")
)
