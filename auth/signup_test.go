package auth

import (
	"context"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store/memory"
)

func newTestDeps() (users *memory.UserStore, audit *memory.AuditStore, log logger.Logger, hasher security.Hasher, ids security.IDGenerator, limiter security.RateLimiter) {
	users = memory.NewUserStore()
	audit = memory.NewAuditStore()
	log = logger.NewConsoleJSONLogger()
	hasher, _ = security.NewBcryptHasher(4)
	ids = security.NewUUIDv7Generator()
	limiter = security.NewInMemoryRateLimiter(1000, time.Minute) // effectively unlimited for these tests
	return
}

func TestSignUp_Success(t *testing.T) {
	users, audit, log, hasher, ids, limiter := newTestDeps()
	ctx := context.Background()

	user, err := SignUp(ctx, users, hasher, ids, limiter, nil, audit, log, "proguy@example.com", "pw", "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.ID == "" {
		t.Error("expected a generated user ID")
	}
	if user.PasswordHash == "pw" {
		t.Error("expected password to be hashed, not stored raw")
	}
}

func TestSignUp_DuplicateEmailRejected(t *testing.T) {
	users, audit, log, hasher, ids, limiter := newTestDeps()
	ctx := context.Background()

	_, err := SignUp(ctx, users, hasher, ids, limiter, nil, audit, log, "proguy@example.com", "pw", "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error on first signup: %v", err)
	}

	_, err = SignUp(ctx, users, hasher, ids, limiter, nil, audit, log, "proguy@example.com", "different-pw", "1.2.3.4")
	if err != ErrUserExists {
		t.Errorf("expected ErrUserExists, got %v", err)
	}
}

func TestSignUp_RateLimited(t *testing.T) {
	users, audit, log, hasher, ids, _ := newTestDeps()
	limiter := security.NewInMemoryRateLimiter(1, time.Minute)
	ctx := context.Background()

	_, err := SignUp(ctx, users, hasher, ids, limiter, nil, audit, log, "a@example.com", "pw", "1.2.3.4")
	if err != nil {
		t.Fatalf("expected first signup to succeed: %v", err)
	}

	_, err = SignUp(ctx, users, hasher, ids, limiter, nil, audit, log, "b@example.com", "pw", "1.2.3.4")
	if err != ErrRateLimited {
		t.Errorf("expected ErrRateLimited for second signup from same IP, got %v", err)
	}
}
