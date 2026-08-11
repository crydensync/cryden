package security

import (
	"context"
	"testing"
	"time"
)

func TestInMemoryRateLimiter_AllowsUpToLimit(t *testing.T) {
	rl := NewInMemoryRateLimiter(3, time.Minute)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		allowed, err := rl.Allow(ctx, "key1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatalf("expected call %d to be allowed", i+1)
		}
	}

	allowed, err := rl.Allow(ctx, "key1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Error("expected 4th call within the window to be denied")
	}
}

func TestInMemoryRateLimiter_KeysAreIndependent(t *testing.T) {
	rl := NewInMemoryRateLimiter(1, time.Minute)
	ctx := context.Background()

	a1, _ := rl.Allow(ctx, "a")
	b1, _ := rl.Allow(ctx, "b")
	if !a1 || !b1 {
		t.Fatal("expected first call for each independent key to be allowed")
	}

	a2, _ := rl.Allow(ctx, "a")
	if a2 {
		t.Error("expected second call for key 'a' to be denied")
	}
}

func TestInMemoryRateLimiter_ResetsAfterWindow(t *testing.T) {
	rl := NewInMemoryRateLimiter(1, 10*time.Millisecond)
	ctx := context.Background()

	first, _ := rl.Allow(ctx, "key1")
	if !first {
		t.Fatal("expected first call to be allowed")
	}

	time.Sleep(20 * time.Millisecond)

	afterWindow, _ := rl.Allow(ctx, "key1")
	if !afterWindow {
		t.Error("expected call after window expiry to be allowed again")
	}
}
