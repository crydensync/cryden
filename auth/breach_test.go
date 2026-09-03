package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
)

// fakeBreachChecker is a controllable test double — reports a fixed
// result (or a fixed error, simulating the check service itself being
// unreachable) and records how many times it was called.
type fakeBreachChecker struct {
	breached bool
	err      error
	calls    int
}

func (f *fakeBreachChecker) IsBreached(ctx context.Context, password string) (bool, error) {
	f.calls++
	return f.breached, f.err
}

func TestSignUp_RejectsBreachedPassword(t *testing.T) {
	users, audit, log, hasher, ids, limiter := newTestDeps()
	ctx := context.Background()
	checker := &fakeBreachChecker{breached: true}

	_, err := SignUp(ctx, users, hasher, ids, limiter, checker, audit, log, "proguy@example.com", "password123", "1.2.3.4")
	if err != ErrPasswordBreached {
		t.Errorf("expected ErrPasswordBreached, got %v", err)
	}
	if checker.calls != 1 {
		t.Errorf("expected the checker to be called exactly once, got %d", checker.calls)
	}
}

func TestSignUp_BreachCheckerErrorFailsOpen(t *testing.T) {
	users, audit, log, hasher, ids, limiter := newTestDeps()
	ctx := context.Background()
	checker := &fakeBreachChecker{err: errors.New("simulated HIBP outage")}

	_, err := SignUp(ctx, users, hasher, ids, limiter, checker, audit, log, "proguy@example.com", "password123", "1.2.3.4")
	if err != nil {
		t.Fatalf("expected signup to succeed (fail open) when the breach checker errors, got %v", err)
	}
}

func TestChangePassword_RejectsBreachedNewPassword(t *testing.T) {
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	audit := memory.NewAuditStore()
	hasher, _ := security.NewBcryptHasher(4)
	log := testLogger{}
	ctx := context.Background()
	checker := &fakeBreachChecker{breached: true}

	hash, _ := hasher.Hash("old-password")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))

	err := ChangePassword(ctx, users, sessions, hasher, checker, audit, log, "user-1", "old-password", "password123")
	if err != ErrPasswordBreached {
		t.Errorf("expected ErrPasswordBreached, got %v", err)
	}
}

func TestChangePassword_WrongCurrentPasswordCheckedBeforeBreach(t *testing.T) {
	// Breach status about a NEW password should never leak to someone
	// who hasn't already proven they own the account.
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	audit := memory.NewAuditStore()
	hasher, _ := security.NewBcryptHasher(4)
	log := testLogger{}
	ctx := context.Background()
	checker := &fakeBreachChecker{breached: true}

	hash, _ := hasher.Hash("old-password")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))

	err := ChangePassword(ctx, users, sessions, hasher, checker, audit, log, "user-1", "totally-wrong", "password123")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials (checked before breach check), got %v", err)
	}
	if checker.calls != 0 {
		t.Errorf("expected the breach checker to never be called before current-password verification, got %d calls", checker.calls)
	}
}

func TestSignUp_BreachRejectionIsAudited(t *testing.T) {
	users, audit, log, hasher, ids, limiter := newTestDeps()
	ctx := context.Background()
	checker := &fakeBreachChecker{breached: true}

	SignUp(ctx, users, hasher, ids, limiter, checker, audit, log, "proguy@example.com", "password123", "1.2.3.4")

	events, err := audit.SearchByType(ctx, store.EventPasswordBreachRejected, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("expected exactly 1 password_breach_rejected event, got %d", len(events))
	}
}
