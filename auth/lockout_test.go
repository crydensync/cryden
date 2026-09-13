package auth

import (
	"context"
	"testing"
	"time"
)

func TestLogin_LocksAccountAfterThreshold(t *testing.T) {
	users, sessions, audit, hasher, ids, refreshGen, jwtIssuer, limiter := newLoginTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("correct-password")
	users.Create(ctx, storeUser("user-1", "proguy@example.com", hash))

	threshold := 3
	for i := 0; i < threshold; i++ {
		_, err := Login(ctx, users, sessions, nil, nil, nil, nil, hasher, ids, refreshGen, jwtIssuer, nil, limiter, audit, log,
			"proguy@example.com", "wrong-password", "1.2.3.4", "test-agent", threshold, time.Minute, noAnomalyThresholds)
		if err != ErrInvalidCredentials {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i+1, err)
		}
	}

	// One more attempt, even with the CORRECT password, must now be
	// rejected as locked — the lock isn't just "N more wrong guesses
	// fail," it blocks everything including a legitimate login.
	_, err := Login(ctx, users, sessions, nil, nil, nil, nil, hasher, ids, refreshGen, jwtIssuer, nil, limiter, audit, log,
		"proguy@example.com", "correct-password", "1.2.3.4", "test-agent", threshold, time.Minute, noAnomalyThresholds)
	if err != ErrAccountLocked {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}
}

func TestLogin_SuccessfulLoginResetsFailedAttempts(t *testing.T) {
	users, sessions, audit, hasher, ids, refreshGen, jwtIssuer, limiter := newLoginTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("correct-password")
	users.Create(ctx, storeUser("user-1", "proguy@example.com", hash))

	threshold := 5
	// Two failed attempts, below threshold.
	for i := 0; i < 2; i++ {
		Login(ctx, users, sessions, nil, nil, nil, nil, hasher, ids, refreshGen, jwtIssuer, nil, limiter, audit, log,
			"proguy@example.com", "wrong-password", "1.2.3.4", "test-agent", threshold, time.Minute, noAnomalyThresholds)
	}

	// A successful login should reset the counter.
	_, err := Login(ctx, users, sessions, nil, nil, nil, nil, hasher, ids, refreshGen, jwtIssuer, nil, limiter, audit, log,
		"proguy@example.com", "correct-password", "1.2.3.4", "test-agent", threshold, time.Minute, noAnomalyThresholds)
	if err != nil {
		t.Fatalf("expected successful login, got %v", err)
	}

	user, _ := users.GetByID(ctx, "user-1")
	if user.FailedAttempts != 0 {
		t.Errorf("expected failed attempts reset to 0 after success, got %d", user.FailedAttempts)
	}
}

func TestLogin_LockExpiresAfterDuration(t *testing.T) {
	users, sessions, audit, hasher, ids, refreshGen, jwtIssuer, limiter := newLoginTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("correct-password")
	users.Create(ctx, storeUser("user-1", "proguy@example.com", hash))

	threshold := 1
	shortLock := 10 * time.Millisecond

	Login(ctx, users, sessions, nil, nil, nil, nil, hasher, ids, refreshGen, jwtIssuer, nil, limiter, audit, log,
		"proguy@example.com", "wrong-password", "1.2.3.4", "test-agent", threshold, shortLock, noAnomalyThresholds)

	// Immediately after: locked.
	_, err := Login(ctx, users, sessions, nil, nil, nil, nil, hasher, ids, refreshGen, jwtIssuer, nil, limiter, audit, log,
		"proguy@example.com", "correct-password", "1.2.3.4", "test-agent", threshold, shortLock, noAnomalyThresholds)
	if err != ErrAccountLocked {
		t.Fatalf("expected ErrAccountLocked immediately after lock, got %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	// After the lock duration passes, login should succeed again.
	_, err = Login(ctx, users, sessions, nil, nil, nil, nil, hasher, ids, refreshGen, jwtIssuer, nil, limiter, audit, log,
		"proguy@example.com", "correct-password", "1.2.3.4", "test-agent", threshold, shortLock, noAnomalyThresholds)
	if err != nil {
		t.Errorf("expected login to succeed after lock expiry, got %v", err)
	}
}
