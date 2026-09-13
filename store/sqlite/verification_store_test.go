package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

func TestVerificationStore_CreateAndGet(t *testing.T) {
	db := newTestDB(t)
	verifications := NewVerificationStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	expires := time.Now().Add(time.Hour)
	if err := verifications.Create(ctx, store.VerificationToken{
		ID: "vt-1", UserID: "user-1", Purpose: store.PurposeEmailChange,
		TokenHash: "th-1", NewEmail: "new@dev.com", ExpiresAt: expires,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	vt, err := verifications.GetByTokenHash(ctx, "th-1")
	if err != nil {
		t.Fatalf("GetByTokenHash: %v", err)
	}
	if vt.ID != "vt-1" || vt.Purpose != store.PurposeEmailChange || vt.NewEmail != "new@dev.com" {
		t.Errorf("wrong row back: %+v", vt)
	}
	// ExpiresAt is caller-supplied — unlike CreatedAt, it is a real
	// parameter in Postgres too — so it must round-trip exactly.
	if !vt.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want %v", vt.ExpiresAt, expires)
	}
	if vt.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero; the store must assign it")
	}
	if vt.UsedAt != nil {
		t.Errorf("UsedAt = %v, want nil for a fresh token", vt.UsedAt)
	}

	if _, err := verifications.GetByTokenHash(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetByTokenHash missing: got %v, want store.ErrNotFound", err)
	}
}

// NewEmail is only populated for email-change tokens. Empty must become
// NULL and come back as "", not fail the scan.
func TestVerificationStore_EmptyNewEmailBecomesNull(t *testing.T) {
	db := newTestDB(t)
	verifications := NewVerificationStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if err := verifications.Create(ctx, store.VerificationToken{
		ID: "vt-1", UserID: "user-1", Purpose: store.PurposeEmailVerify,
		TokenHash: "th-1", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	var nulls int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM verification_tokens WHERE new_email IS NULL`).Scan(&nulls); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if nulls != 1 {
		t.Errorf("%d rows with a NULL new_email, want 1", nulls)
	}

	vt, err := verifications.GetByTokenHash(ctx, "th-1")
	if err != nil {
		t.Fatalf("GetByTokenHash: %v", err)
	}
	if vt.NewEmail != "" {
		t.Errorf("NewEmail = %q, want empty", vt.NewEmail)
	}
}

// An expired token still has to be findable: the auth layer needs to
// tell "this link has expired" apart from "this link was never real",
// and it can only do that if the row comes back.
func TestVerificationStore_ExpiredTokensAreStillReturned(t *testing.T) {
	db := newTestDB(t)
	verifications := NewVerificationStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	past := time.Now().Add(-time.Hour)
	if err := verifications.Create(ctx, store.VerificationToken{
		ID: "vt-1", UserID: "user-1", Purpose: store.PurposeMagicLink,
		TokenHash: "th-1", ExpiresAt: past,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	vt, err := verifications.GetByTokenHash(ctx, "th-1")
	if err != nil {
		t.Fatalf("an expired token must still be found: %v", err)
	}
	if !vt.ExpiresAt.Before(time.Now()) {
		t.Errorf("ExpiresAt = %v, expected it in the past", vt.ExpiresAt)
	}
}

// Single-use is enforced by the UPDATE's own WHERE clause, not by a
// read-then-write, so two racing redemptions cannot both win.
func TestVerificationStore_MarkUsedIsSingleUse(t *testing.T) {
	db := newTestDB(t)
	verifications := NewVerificationStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if err := verifications.Create(ctx, store.VerificationToken{
		ID: "vt-1", UserID: "user-1", Purpose: store.PurposeEmailVerify,
		TokenHash: "th-1", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := verifications.MarkUsed(ctx, "vt-1"); err != nil {
		t.Fatalf("first MarkUsed: %v", err)
	}
	if err := verifications.MarkUsed(ctx, "vt-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second MarkUsed: got %v, want store.ErrNotFound — the token would be reusable", err)
	}
	if err := verifications.MarkUsed(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("MarkUsed on a missing token: got %v, want store.ErrNotFound", err)
	}

	vt, err := verifications.GetByTokenHash(ctx, "th-1")
	if err != nil {
		t.Fatalf("GetByTokenHash: %v", err)
	}
	if vt.UsedAt == nil {
		t.Error("UsedAt is nil after MarkUsed")
	}
}

func TestVerificationStore_DuplicateTokenHashRejected(t *testing.T) {
	db := newTestDB(t)
	verifications := NewVerificationStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	vt := store.VerificationToken{
		ID: "vt-1", UserID: "user-1", Purpose: store.PurposeEmailVerify,
		TokenHash: "th-1", ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := verifications.Create(ctx, vt); err != nil {
		t.Fatalf("Create: %v", err)
	}
	vt.ID = "vt-2"
	if err := verifications.Create(ctx, vt); err == nil {
		t.Error("a second token with the same hash was accepted")
	}
}
