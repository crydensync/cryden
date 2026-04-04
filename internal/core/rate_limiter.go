package core

import (
    "context"
    "sync"
    "time"
)

// LimitResult contains rate limit info for response headers
type LimitResult struct {
    Allowed   bool
    Limit     int
    Remaining int
    Reset     time.Duration
}

// RateLimiter defines how rate limiting works
type RateLimiter interface {
    // Allow checks if request is permitted
    Allow(ctx context.Context, key string) (LimitResult, error)
    
    // Reset clears limit for a key
    Reset(ctx context.Context, key string) error
}

// MemoryRateLimiter implements RateLimiter in memory
type MemoryRateLimiter struct {
    mu       sync.RWMutex
    attempts map[string][]time.Time
    limit    int
    window   time.Duration
}

// NewMemoryRateLimiter creates a new memory rate limiter
func NewMemoryRateLimiter(limit int, window time.Duration) *MemoryRateLimiter {
    return &MemoryRateLimiter{
        attempts: make(map[string][]time.Time),
        limit:    limit,
        window:   window,
    }
}

// Allow checks if a request is within rate limit
func (r *MemoryRateLimiter) Allow(ctx context.Context, key string) (LimitResult, error) {
    r.mu.Lock()
    defer r.mu.Unlock()

    now := time.Now()
    cutoff := now.Add(-r.window)

    // Clean old attempts
    attempts := r.attempts[key]
    valid := make([]time.Time, 0)
    for _, t := range attempts {
        if t.After(cutoff) {
            valid = append(valid, t)
        }
    }

    // Check if under limit (strict: < limit means allowed)
    if len(valid) < r.limit {
        // Add current attempt
        valid = append(valid, now)
        r.attempts[key] = valid

        remaining := r.limit - len(valid)
        if remaining < 0 {
            remaining = 0
        }

        return LimitResult{
            Allowed:   true,
            Limit:     r.limit,
            Remaining: remaining,
            Reset:     0,
        }, nil
    }

    // Rate limited
    oldest := valid[0]
    resetTime := oldest.Add(r.window)
    resetDuration := time.Until(resetTime)
    if resetDuration < 0 {
        resetDuration = 0
    }

    return LimitResult{
        Allowed:   false,
        Limit:     r.limit,
        Remaining: 0,
        Reset:     resetDuration,
    }, nil
}

// Reset clears rate limit for a key
func (r *MemoryRateLimiter) Reset(ctx context.Context, key string) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    delete(r.attempts, key)
    return nil
}

// NoopRateLimiter for testing - allows everything
type NoopRateLimiter struct{}

func (r *NoopRateLimiter) Allow(ctx context.Context, key string) (LimitResult, error) {
    return LimitResult{
        Allowed:   true,
        Limit:     0,
        Remaining: 0,
        Reset:     0,
    }, nil
}

func (r *NoopRateLimiter) Reset(ctx context.Context, key string) error {
    return nil
}
