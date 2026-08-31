package auth

import (
	"context"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"
)

func newLoginTestDeps(t *testing.T) (*memory.UserStore, *memory.SessionStore, *memory.AuditStore, security.Hasher, security.IDGenerator, token.TokenGenerator, *token.JWTIssuer, security.RateLimiter) {
	t.Helper()
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	audit := memory.NewAuditStore()
	hasher, _ := security.NewBcryptHasher(4)
	ids := security.NewUUIDv7Generator()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	limiter := security.NewInMemoryRateLimiter(1000, time.Minute)
	return users, sessions, audit, hasher, ids, refreshGen, jwtIssuer, limiter
}

func TestLogin_Success(t *testing.T) {
	users, sessions, audit, hasher, ids, refreshGen, jwtIssuer, limiter := newLoginTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("correct-password")
	users.Create(ctx, storeUser("user-1", "proguy@example.com", hash))

	// totpStore/pendingIssuer are nil — TOTP not configured for this
	// engine, Login must behave exactly as it did before TOTP existed.
	tokens, err := Login(ctx, users, sessions, nil, nil, hasher, ids, refreshGen, jwtIssuer, nil, limiter, audit, log,
		"proguy@example.com", "correct-password", "1.2.3.4", "test-agent", 5, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Error("expected both tokens to be populated")
	}
}

func TestLogin_WrongPasswordRejected(t *testing.T) {
	users, sessions, audit, hasher, ids, refreshGen, jwtIssuer, limiter := newLoginTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("correct-password")
	users.Create(ctx, storeUser("user-1", "proguy@example.com", hash))

	_, err := Login(ctx, users, sessions, nil, nil, hasher, ids, refreshGen, jwtIssuer, nil, limiter, audit, log,
		"proguy@example.com", "wrong-password", "1.2.3.4", "test-agent", 5, time.Minute)
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLogin_NonexistentUserRejectedWithSameError(t *testing.T) {
	// Critical: must return the SAME error as wrong-password, to avoid
	// leaking which emails are registered (enumeration attack).
	users, sessions, audit, hasher, ids, refreshGen, jwtIssuer, limiter := newLoginTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	_, err := Login(ctx, users, sessions, nil, nil, hasher, ids, refreshGen, jwtIssuer, nil, limiter, audit, log,
		"nobody@example.com", "any-password", "1.2.3.4", "test-agent", 5, time.Minute)
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials (same as wrong password), got %v", err)
	}
}

func TestLogin_NonexistentUserTimingMatchesWrongPassword(t *testing.T) {
	// Regression test for the timing side-channel: before the fix,
	// the nonexistent-user path returned before ever calling
	// hasher.Compare, making it measurably faster than a real
	// wrong-password attempt and letting an attacker enumerate
	// registered emails by response time alone even though the
	// returned error was already identical. A real cost-4 bcrypt
	// hash still takes single-digit milliseconds, so both paths
	// should land in the same rough band, not orders of magnitude
	// apart. This is a coarse smoke test, not a precise timing
	// analysis — its job is to catch a future regression that removes
	// the dummy hasher.Hash call entirely, not to certify
	// constant-time behavior.
	users, sessions, audit, hasher, ids, refreshGen, jwtIssuer, limiter := newLoginTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("correct-password")
	users.Create(ctx, storeUser("user-1", "proguy@example.com", hash))

	start := time.Now()
	Login(ctx, users, sessions, nil, nil, hasher, ids, refreshGen, jwtIssuer, nil, limiter, audit, log,
		"proguy@example.com", "wrong-password", "1.2.3.4", "test-agent", 5, time.Minute)
	wrongPasswordDuration := time.Since(start)

	start = time.Now()
	Login(ctx, users, sessions, nil, nil, hasher, ids, refreshGen, jwtIssuer, nil, limiter, audit, log,
		"nobody@example.com", "any-password", "1.2.3.4", "test-agent", 5, time.Minute)
	nonexistentUserDuration := time.Since(start)

	// Nonexistent-user path should never be dramatically faster —
	// allow a generous 2x margin either direction for test-runner
	// noise, since this isn't a precision timing measurement.
	ratio := float64(nonexistentUserDuration) / float64(wrongPasswordDuration)
	if ratio < 0.5 {
		t.Errorf("nonexistent-user login returned %v, wrong-password returned %v (ratio %.2f) — the dummy hash may not be running", nonexistentUserDuration, wrongPasswordDuration, ratio)
	}
}
