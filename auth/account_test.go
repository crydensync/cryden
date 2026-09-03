package auth

import (
	"context"
	"testing"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
)

func TestChangePassword_Success(t *testing.T) {
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	audit := memory.NewAuditStore()
	hasher, _ := security.NewBcryptHasher(4)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("old-password")
	users.Create(ctx, storeUser("user-1", "proguy@example.com", hash))
	sessions.Create(ctx, store.Session{ID: "s1", FamilyID: "s1", UserID: "user-1"})

	err := ChangePassword(ctx, users, sessions, hasher, nil, audit, log, "user-1", "old-password", "new-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, _ := users.GetByID(ctx, "user-1")
	if hasher.Compare(updated.PasswordHash, "new-password") != nil {
		t.Error("expected password hash to match the new password")
	}

	// All sessions must be revoked as a side effect.
	s, _ := sessions.GetByID(ctx, "s1")
	if s.RevokedAt == nil {
		t.Error("expected existing session to be revoked after password change")
	}
}

func TestChangePassword_RejectsWrongCurrentPassword(t *testing.T) {
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	audit := memory.NewAuditStore()
	hasher, _ := security.NewBcryptHasher(4)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("old-password")
	users.Create(ctx, storeUser("user-1", "proguy@example.com", hash))

	err := ChangePassword(ctx, users, sessions, hasher, nil, audit, log, "user-1", "totally-wrong", "new-password")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}

	// Password must be UNCHANGED after a rejected attempt.
	unchanged, _ := users.GetByID(ctx, "user-1")
	if hasher.Compare(unchanged.PasswordHash, "old-password") != nil {
		t.Error("expected password to remain the old one after a rejected change")
	}
}

func TestDeleteAccount_Success(t *testing.T) {
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	audit := memory.NewAuditStore()
	hasher, _ := security.NewBcryptHasher(4)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("correct-password")
	users.Create(ctx, storeUser("user-1", "proguy@example.com", hash))

	err := DeleteAccount(ctx, users, sessions, hasher, audit, log, "user-1", "correct-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := users.GetByID(ctx, "user-1"); err != store.ErrNotFound {
		t.Error("expected user to be deleted")
	}
}

func TestDeleteAccount_RejectsWrongPassword(t *testing.T) {
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	audit := memory.NewAuditStore()
	hasher, _ := security.NewBcryptHasher(4)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("correct-password")
	users.Create(ctx, storeUser("user-1", "proguy@example.com", hash))

	err := DeleteAccount(ctx, users, sessions, hasher, audit, log, "user-1", "wrong-password")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}

	// Account must still exist after a rejected delete attempt.
	if _, err := users.GetByID(ctx, "user-1"); err != nil {
		t.Error("expected user to still exist after a rejected delete")
	}
}
