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
	users.Create(ctx, storeUser("user-1", "alice@example.com", hash))

	tokens, err := Login(ctx, users, sessions, hasher, ids, refreshGen, jwtIssuer, limiter, audit, log,
		"alice@example.com", "correct-password", "1.2.3.4", "test-agent", 5, time.Minute)
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
	users.Create(ctx, storeUser("user-1", "alice@example.com", hash))

	_, err := Login(ctx, users, sessions, hasher, ids, refreshGen, jwtIssuer, limiter, audit, log,
		"alice@example.com", "wrong-password", "1.2.3.4", "test-agent", 5, time.Minute)
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

	_, err := Login(ctx, users, sessions, hasher, ids, refreshGen, jwtIssuer, limiter, audit, log,
		"nobody@example.com", "any-password", "1.2.3.4", "test-agent", 5, time.Minute)
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials (same as wrong password), got %v", err)
	}
}