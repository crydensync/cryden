package sqlite

import (
	"context"
	"errors"
	"testing"

	"github.com/crydensync/cryden/v2/store"
)

func TestTOTPStore_UpsertAndGet(t *testing.T) {
	db := newTestDB(t)
	totp := NewTOTPStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if err := totp.Upsert(ctx, store.TOTPSecret{UserID: "user-1", EncryptedSecret: "enc-1"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	secret, err := totp.GetByUserID(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetByUserID: %v", err)
	}
	if secret.EncryptedSecret != "enc-1" {
		t.Errorf("EncryptedSecret = %q, want enc-1", secret.EncryptedSecret)
	}
	// Unconfirmed until the user proves possession. A non-nil
	// ConfirmedAt here would mean a brand-new secret could gate a login.
	if secret.ConfirmedAt != nil {
		t.Errorf("ConfirmedAt = %v, want nil for a fresh secret", secret.ConfirmedAt)
	}
	if secret.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero; the store must assign it")
	}

	if _, err := totp.GetByUserID(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetByUserID missing: got %v, want store.ErrNotFound", err)
	}
}

// Re-enrolling produces a new secret, and the confirmation that proved
// possession of the old one says nothing about this one. Carrying
// confirmed_at over would let an unverified secret gate logins.
func TestTOTPStore_UpsertResetsConfirmation(t *testing.T) {
	db := newTestDB(t)
	totp := NewTOTPStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if err := totp.Upsert(ctx, store.TOTPSecret{UserID: "user-1", EncryptedSecret: "enc-1"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := totp.Confirm(ctx, "user-1"); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	confirmed, err := totp.GetByUserID(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetByUserID: %v", err)
	}
	if confirmed.ConfirmedAt == nil {
		t.Fatal("ConfirmedAt is nil after Confirm")
	}

	if err := totp.Upsert(ctx, store.TOTPSecret{UserID: "user-1", EncryptedSecret: "enc-2"}); err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	after, err := totp.GetByUserID(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetByUserID: %v", err)
	}
	if after.EncryptedSecret != "enc-2" {
		t.Errorf("EncryptedSecret = %q, want enc-2 — the upsert did not replace the secret", after.EncryptedSecret)
	}
	if after.ConfirmedAt != nil {
		t.Errorf("ConfirmedAt = %v after re-enrolment, want nil", after.ConfirmedAt)
	}

	// One row per user, never two: the primary key is user_id.
	var rows int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM totp_secrets`).Scan(&rows); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if rows != 1 {
		t.Errorf("%d rows after two Upserts, want 1", rows)
	}
}

func TestTOTPStore_ConfirmAndDeleteReportMissingRows(t *testing.T) {
	db := newTestDB(t)
	totp := NewTOTPStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if err := totp.Confirm(ctx, "user-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Confirm with no secret pending: got %v, want store.ErrNotFound", err)
	}
	if err := totp.Delete(ctx, "user-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Delete with no secret: got %v, want store.ErrNotFound", err)
	}

	if err := totp.Upsert(ctx, store.TOTPSecret{UserID: "user-1", EncryptedSecret: "enc-1"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := totp.Delete(ctx, "user-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := totp.GetByUserID(ctx, "user-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after Delete: got %v, want store.ErrNotFound", err)
	}
}
