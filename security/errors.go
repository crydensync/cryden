package security

import "errors"

var (
	ErrInvalidBcryptCost = errors.New("security: bcrypt cost out of valid range")

	// Reported by NewRedisRateLimiter / NewRedisRateLimiterWithPrefix,
	// which validate their arguments because a host constructs that
	// limiter directly — there is no Config.applyDefaults between the
	// caller and it to turn a zero value into something sane.
	ErrNilRedisClient    = errors.New("security: redis rate limiter requires a redis client")
	ErrInvalidRateLimit  = errors.New("security: rate limit must allow at least one call per window")
	ErrInvalidRateWindow = errors.New("security: rate limit window must be at least one millisecond")

	// Reported by Argon2idHasher and, for the two hash-shaped ones, by
	// MultiHasher on its behalf. ErrPasswordMismatch is the Argon2id
	// counterpart to bcrypt.ErrMismatchedHashAndPassword: auth/ collapses
	// every Compare error into ErrInvalidCredentials, so these exist for
	// operators reading logs and for tests, not for callers to branch on.
	ErrInvalidArgon2idParams  = errors.New("security: argon2id parameters out of valid range")
	ErrPasswordMismatch       = errors.New("security: password does not match hash")
	ErrMalformedHash          = errors.New("security: stored hash is not in a readable format")
	ErrUnsupportedHashVersion = errors.New("security: stored hash uses an unsupported algorithm version")
)
