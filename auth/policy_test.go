package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store/memory"
)

func TestSignUp_RejectsPasswordViolatingPolicy(t *testing.T) {
	users, audit, log, hasher, ids, limiter := newTestDeps()
	ctx := context.Background()
	policy := security.PasswordPolicy{MinLength: 8}

	_, err := SignUp(ctx, users, hasher, ids, limiter, nil, audit, log, policy, "proguy@example.com", "short", "1.2.3.4")
	var violation *ErrPasswordPolicyViolation
	if !errors.As(err, &violation) {
		t.Fatalf("expected *ErrPasswordPolicyViolation, got %v", err)
	}
	if len(violation.Violations) != 1 || violation.Violations[0] != "min_length" {
		t.Errorf("expected [\"min_length\"], got %v", violation.Violations)
	}
}

func TestSignUp_AcceptsPasswordMeetingPolicy(t *testing.T) {
	users, audit, log, hasher, ids, limiter := newTestDeps()
	ctx := context.Background()
	policy := security.PasswordPolicy{MinLength: 8}

	_, err := SignUp(ctx, users, hasher, ids, limiter, nil, audit, log, policy, "proguy@example.com", "Tr0ubl3-Fr33!2026", "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSignUp_PolicyCheckedBeforeBreachCheck(t *testing.T) {
	// The breach checker should never be called for a password that
	// already fails the (cheap, local) policy check — no reason to
	// make an external call for input that's already rejected.
	users, audit, log, hasher, ids, limiter := newTestDeps()
	ctx := context.Background()
	checker := &fakeBreachChecker{breached: true}
	policy := security.PasswordPolicy{MinLength: 20}

	_, err := SignUp(ctx, users, hasher, ids, limiter, checker, audit, log, policy, "proguy@example.com", "short", "1.2.3.4")
	var violation *ErrPasswordPolicyViolation
	if !errors.As(err, &violation) {
		t.Fatalf("expected *ErrPasswordPolicyViolation, got %v", err)
	}
	if checker.calls != 0 {
		t.Errorf("expected the breach checker to never be called, got %d calls", checker.calls)
	}
}

func TestChangePassword_RejectsPasswordViolatingPolicy(t *testing.T) {
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	audit := memory.NewAuditStore()
	hasher, _ := security.NewBcryptHasher(4)
	log := testLogger{}
	ctx := context.Background()
	policy := security.PasswordPolicy{MinLength: 8}

	hash, _ := hasher.Hash("old-password")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))

	err := ChangePassword(ctx, users, sessions, hasher, nil, audit, log, policy, "user-1", "old-password", "short")
	var violation *ErrPasswordPolicyViolation
	if !errors.As(err, &violation) {
		t.Fatalf("expected *ErrPasswordPolicyViolation, got %v", err)
	}
}

func TestChangePassword_WrongCurrentPasswordCheckedBeforePolicy(t *testing.T) {
	// Policy details about a NEW password should never leak to
	// someone who hasn't already proven they own the account.
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	audit := memory.NewAuditStore()
	hasher, _ := security.NewBcryptHasher(4)
	log := testLogger{}
	ctx := context.Background()
	policy := security.PasswordPolicy{MinLength: 8}

	hash, _ := hasher.Hash("old-password")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))

	err := ChangePassword(ctx, users, sessions, hasher, nil, audit, log, policy, "user-1", "totally-wrong", "short")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials (checked before policy), got %v", err)
	}
}
