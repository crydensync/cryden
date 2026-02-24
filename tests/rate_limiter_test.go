package tests

import (
	"context"
	"testing"
	"time"

	"github.com/raymondproguy/credensync/core"
)

func TestMemoryRateLimiter(t *testing.T) {
	limiter := core.NewMemoryRateLimiter(3, time.Second)
	ctx := context.Background()
	key := "test-ip-123"

	t.Run("allows within limit", func(t *testing.T) {
		// First 3 attempts should be allowed
		for i := 0; i < 3; i++ {
			result, err := limiter.Allow(ctx, key)
			if err != nil {
				t.Fatalf("Allow failed: %v", err)
			}
			if !result.Allowed {
				t.Errorf("Attempt %d should be allowed", i+1)
			}
			if result.Remaining != 3-(i+1) {
				t.Errorf("Expected remaining %d, got %d", 3-(i+1), result.Remaining)
			}
		}
	})

	t.Run("blocks after limit", func(t *testing.T) {
		// 4th attempt should be blocked
		result, err := limiter.Allow(ctx, key)
		if err != nil {
			t.Fatalf("Allow failed: %v", err)
		}
		if result.Allowed {
			t.Error("Attempt should be blocked")
		}
		if result.Remaining != 0 {
			t.Errorf("Expected remaining 0, got %d", result.Remaining)
		}
		if result.Reset <= 0 {
			t.Error("Expected positive reset time")
		}
	})

	t.Run("reset works", func(t *testing.T) {
		err := limiter.Reset(ctx, key)
		if err != nil {
			t.Fatalf("Reset failed: %v", err)
		}

		result, err := limiter.Allow(ctx, key)
		if err != nil {
			t.Fatalf("Allow failed: %v", err)
		}
		if !result.Allowed {
			t.Error("After reset, should be allowed")
		}
	})

	t.Run("different keys are independent", func(t *testing.T) {
		key1 := "ip-1"
		key2 := "ip-2"

		// Use up key1
		for i := 0; i < 3; i++ {
			limiter.Allow(ctx, key1)
		}

		// key1 should be blocked
		result1, _ := limiter.Allow(ctx, key1)
		if result1.Allowed {
			t.Error("key1 should be blocked")
		}

		// key2 should still work
		result2, _ := limiter.Allow(ctx, key2)
		if !result2.Allowed {
			t.Error("key2 should be allowed")
		}
	})
}

func TestNoopRateLimiter(t *testing.T) {
	limiter := &core.NoopRateLimiter{}
	ctx := context.Background()

	t.Run("always allows", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			result, err := limiter.Allow(ctx, "any-key")
			if err != nil {
				t.Fatalf("Allow failed: %v", err)
			}
			if !result.Allowed {
				t.Error("Noop should always allow")
			}
		}
	})
}
