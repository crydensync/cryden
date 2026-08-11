package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
)

func TestPostgresVerificationStore_CreateAndGetByTokenHash(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	vs := NewVerificationStore(db)
	ctx := context.Background()

	userID := createTestUser(t, us)
	defer us.Delete(ctx, userID)

	ids := security.NewUUIDv7Generator()
	vtID, _ := ids.New()

	vt := store.VerificationToken{
		ID:        vtID,
		UserID:    userID,
		Purpose:   store.PurposeEmailChange,
		TokenHash: "test-hash-xyz",
		NewEmail:  "new-" + uniqueEmail(t),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	if err := vs.Create(ctx, vt); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	got, err := vs.GetByTokenHash(ctx, "test-hash-xyz")
	if err != nil {
		t.Fatalf("GetByTokenHash failed: %v", err)
	}
	if got.UserID != userID {
		t.Errorf("expected user %s, got %s", userID, got.UserID)
	}
	if got.Purpose != store.PurposeEmailChange {
		t.Errorf("expected PurposeEmailChange, got %s", got.Purpose)
	}
	if got.NewEmail != vt.NewEmail {
		t.Errorf("expected NewEmail %s, got %s", vt.NewEmail, got.NewEmail)
	}
	if got.UsedAt != nil {
		t.Error("expected UsedAt to be nil for a fresh token")
	}
}

func TestPostgresVerificationStore_GetByTokenHash_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	vs := NewVerificationStore(db)
	ctx := context.Background()

	_, err := vs.GetByTokenHash(ctx, "never-issued-hash")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestPostgresVerificationStore_MarkUsed(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	vs := NewVerificationStore(db)
	ctx := context.Background()

	userID := createTestUser(t, us)
	defer us.Delete(ctx, userID)

	ids := security.NewUUIDv7Generator()
	vtID, _ := ids.New()
	vs.Create(ctx, store.VerificationToken{
		ID: vtID, UserID: userID, Purpose: store.PurposeEmailVerify,
		TokenHash: "mark-used-hash", ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	if err := vs.MarkUsed(ctx, vtID); err != nil {
		t.Fatalf("MarkUsed failed: %v", err)
	}

	got, _ := vs.GetByTokenHash(ctx, "mark-used-hash")
	if got.UsedAt == nil {
		t.Error("expected UsedAt to be set after MarkUsed")
	}

	// Marking an already-used token again must fail — enforces the
	// single-use guarantee at the DB layer, not just application logic.
	if err := vs.MarkUsed(ctx, vtID); err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound marking an already-used token again, got %v", err)
	}
}
