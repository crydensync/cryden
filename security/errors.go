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
)
