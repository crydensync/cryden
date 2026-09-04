package security

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultRedisKeyPrefix namespaces every key RedisRateLimiter touches.
// Redis is normally shared with whatever else the host app keeps there,
// and the keys this limiter is handed are opaque caller-built strings
// (auth passes "login:"+ip+":"+email, "signup:"+ip, and similar) — with
// no prefix, a counter and an unrelated application key could collide
// on a name neither side chose deliberately.
const DefaultRedisKeyPrefix = "cryden:ratelimit:"

// redisFixedWindowLimit is the entire limiter: one INCR that creates the
// counter, one PEXPIRE that closes the window it belongs to, and one
// comparison against the limit. It is a script because those steps have
// to be a single atomic operation — the whole point of counting in Redis
// is that several engine instances share one counter, and a plain
// INCR-then-PEXPIRE issued from Go lets two of them interleave: both
// INCR to 1, both arm an expiry, and one window quietly becomes two.
//
// The PTTL branch covers a counter that exists with no expiry at all —
// a key set by hand, or one left behind by a process that died between
// the INCR and the PEXPIRE of some older non-atomic implementation.
// Without it that key would count up forever and deny its caller
// permanently; with it, the next call re-arms the window and the
// counter heals itself.
var redisFixedWindowLimit = redis.NewScript(`
local hits = redis.call("INCR", KEYS[1])
if hits == 1 or redis.call("PTTL", KEYS[1]) < 0 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
if hits > tonumber(ARGV[2]) then
  return 0
end
return 1
`)

// RedisRateLimiter is the distributed RateLimiter implementation: the
// same fixed-window-counter-per-key policy InMemoryRateLimiter applies,
// with the counter kept in Redis so every engine instance pointed at
// that Redis shares one window. Swapping one for the other changes where
// the count lives, not what counts as over the limit.
//
// Unlike BreachedPasswordChecker or IPGeolocator — interfaces the engine
// deliberately ships no implementation of, because using them means
// calling somebody else's internet service — Redis is infrastructure the
// host app configures and operates, the same category as Postgres. So
// this is a real implementation, and like every store it takes an
// already-constructed client rather than a connection string it would
// dial itself.
//
// Operationally, wiring this makes Redis a hard dependency of the three
// entry points that rate-limit: SignUp, Login and RequestMagicLink each
// propagate a limiter error to their caller rather than guessing, so
// while Redis is unreachable those calls fail instead of running
// unlimited. Failing closed is the safe direction and it is deliberate,
// but it is a real availability trade-off, and a host that would rather
// stay open can wrap this in its own RateLimiter that swallows the error
// and returns true — that is a decision only the host can make.
//
// Works with a *redis.Client, *redis.ClusterClient or *redis.Ring: every
// Allow touches exactly one key, so there is no multi-slot script for
// Cluster to reject. The client stays owned by the host app; this type
// never closes it.
type RedisRateLimiter struct {
	client    redis.Scripter
	limit     int
	window    time.Duration
	keyPrefix string
}

var _ RateLimiter = (*RedisRateLimiter)(nil)

// NewRedisRateLimiter constructs a limiter allowing `limit` calls per
// `window` per key, counted in the Redis that `client` talks to, under
// DefaultRedisKeyPrefix. Like NewInMemoryRateLimiter, both bounds are
// the caller's to set — there are no hidden defaults here — but unlike
// it, they are validated, because a limiter a host constructs itself has
// no Config.applyDefaults upstream of it to fill in a zero value.
func NewRedisRateLimiter(client redis.Scripter, limit int, window time.Duration) (*RedisRateLimiter, error) {
	return NewRedisRateLimiterWithPrefix(client, limit, window, DefaultRedisKeyPrefix)
}

// NewRedisRateLimiterWithPrefix is NewRedisRateLimiter with the key
// namespace chosen explicitly, for two deployments that share one Redis
// database and must not share counters — staging alongside production,
// or one namespace per tenant. Passing "" is allowed and means exactly
// what it says: raw caller-supplied keys, no prefix, appropriate when
// the database belongs to this engine alone.
func NewRedisRateLimiterWithPrefix(client redis.Scripter, limit int, window time.Duration, keyPrefix string) (*RedisRateLimiter, error) {
	if client == nil {
		return nil, ErrNilRedisClient
	}
	if limit <= 0 {
		return nil, ErrInvalidRateLimit
	}
	// PEXPIRE's unit is the floor: a window that rounds down to zero
	// milliseconds makes Redis reject the expiry outright rather than
	// approximate it, so the counter would never expire. This is the one
	// place the two implementations are not interchangeable —
	// InMemoryRateLimiter compares deadlines and has no such floor.
	if window < time.Millisecond {
		return nil, ErrInvalidRateWindow
	}
	return &RedisRateLimiter{
		client:    client,
		limit:     limit,
		window:    window,
		keyPrefix: keyPrefix,
	}, nil
}

// Allow counts this call against `key`'s current window and reports
// whether it is within the limit. One round trip (EVALSHA), plus one
// extra the first time this process meets a Redis that has not cached
// the script yet, which go-redis retries as a full EVAL by itself.
func (r *RedisRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	verdict, err := redisFixedWindowLimit.Run(
		ctx,
		r.client,
		[]string{r.keyPrefix + key},
		r.window.Milliseconds(),
		r.limit,
	).Int64()
	if err != nil {
		// Deny on error, never "allowed, but also here is an error": a
		// caller that read the bool and ignored err would otherwise run
		// completely unlimited for as long as Redis stayed down.
		return false, fmt.Errorf("security: redis rate limiter: %w", err)
	}
	return verdict == 1, nil
}
