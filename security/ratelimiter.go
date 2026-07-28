package security

import (
	"context"
	"sync"
	"time"
)

// RateLimiter defines a generic allow/deny check keyed by an opaque
// string. The limiter has no knowledge of what the key represents —
// callers decide (e.g. ip+":"+email for login attempts). This keeps
// the engine framework-agnostic: it never infers a caller's identity
// or IP itself, it only receives what's passed in.
type RateLimiter interface {
	Allow(ctx context.Context, key string) (bool, error)
}

// InMemoryRateLimiter is the v2 RateLimiter implementation: a simple
// fixed-window counter per key. Not distributed — fine for a single
// process; a Redis-backed implementation is a later addition, not v2.
type InMemoryRateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	counters map[string]*windowCounter
}

type windowCounter struct {
	count     int
	windowEnd time.Time
}

// NewInMemoryRateLimiter constructs a limiter allowing `limit` calls
// per `window` duration, per key. Both must be set explicitly by the
// caller via Config — no hidden default limits.
func NewInMemoryRateLimiter(limit int, window time.Duration) *InMemoryRateLimiter {
	return &InMemoryRateLimiter{
		limit:    limit,
		window:   window,
		counters: make(map[string]*windowCounter),
	}
}

func (r *InMemoryRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	c, ok := r.counters[key]
	if !ok || now.After(c.windowEnd) {
		r.counters[key] = &windowCounter{count: 1, windowEnd: now.Add(r.window)}
		return true, nil
	}
	if c.count >= r.limit {
		return false, nil
	}
	c.count++
	return true, nil
}
