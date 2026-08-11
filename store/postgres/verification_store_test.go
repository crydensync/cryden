package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
)

func uniqueEmail(t *testing.T) string {
	t.Helper()
	ids := security.NewUUIDv7Generator()
	id, _ := ids.New()
	return "test-" + id + "@example.com"
}

func TestPostgresUserStore_CreateAndGet(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	ctx := context.Background()

	ids := security.NewUUIDv7Generator()
	userID, _ := ids.New()
	email := uniqueEmail(t)

	err := us.Create(ctx, store.User{ID: userID, Email: email, PasswordHash: "hash"})
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	defer us.Delete(ctx, userID)

	byEmail, err := us.GetByEmail(ctx, email)
	if err != nil {
		t.Fatalf("GetByEmail failed: %v", err)
	}
	if byEmail.ID != userID {
		t.Errorf("expected ID %s, got %s", userID, byEmail.ID)
	}

	byID, err := us.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if byID.Email != email {
		t.Errorf("expected email %s, got %s", email, byID.Email)
	}
}

func TestPostgresUserStore_GetByEmail_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	ctx := context.Background()

	_, err := us.GetByEmail(ctx, "definitely-not-a-real-user@example.com")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestPostgresUserStore_DuplicateEmailRejectedByDB(t *testing.T) {
	// The application layer also checks for duplicates, but the DB's
	// UNIQUE constraint on email is the real backstop — verify it
	// actually rejects a second insert at the DB level.
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	ctx := context.Background()

	ids := security.NewUUIDv7Generator()
	id1, _ := ids.New()
	id2, _ := ids.New()
	email := uniqueEmail(t)

	if err := us.Create(ctx, store.User{ID: id1, Email: email, PasswordHash: "hash"}); err != nil {
		t.Fatalf("first create failed: %v", err)
	}
	defer us.Delete(ctx, id1)

	if err := us.Create(ctx, store.User{ID: id2, Email: email, PasswordHash: "hash"}); err == nil {
		t.Error("expected duplicate email insert to fail at the DB level, got nil error")
	}
}

func TestPostgresUserStore_UpdatePasswordHash(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	ctx := context.Background()

	ids := security.NewUUIDv7Generator()
	userID, _ := ids.New()
	us.Create(ctx, store.User{ID: userID, Email: uniqueEmail(t), PasswordHash: "old-hash"})
	defer us.Delete(ctx, userID)

	if err := us.UpdatePasswordHash(ctx, userID, "new-hash"); err != nil {
		t.Fatalf("update failed: %v", err)
	}

	u, _ := us.GetByID(ctx, userID)
	if u.PasswordHash != "new-hash" {
		t.Errorf("expected new-hash, got %s", u.PasswordHash)
	}
}

func TestPostgresUserStore_UpdateEmail(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	ctx := context.Background()

	ids := security.NewUUIDv7Generator()
	userID, _ := ids.New()
	us.Create(ctx, store.User{ID: userID, Email: uniqueEmail(t), PasswordHash: "hash"})
	defer us.Delete(ctx, userID)

	newEmail := uniqueEmail(t)
	if err := us.UpdateEmail(ctx, userID, newEmail); err != nil {
		t.Fatalf("update failed: %v", err)
	}

	u, _ := us.GetByID(ctx, userID)
	if u.Email != newEmail {
		t.Errorf("expected %s, got %s", newEmail, u.Email)
	}
}

func TestPostgresUserStore_Delete(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	ctx := context.Background()

	ids := security.NewUUIDv7Generator()
	userID, _ := ids.New()
	us.Create(ctx, store.User{ID: userID, Email: uniqueEmail(t), PasswordHash: "hash"})

	if err := us.Delete(ctx, userID); err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	if _, err := us.GetByID(ctx, userID); err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestPostgresUserStore_LockoutLifecycle(t *testing.T) {
	// This is the property that matters most for lockout: it must be
	// real, persistent DB state — not something that could reset on
	// restart the way an in-memory counter would.
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	ctx := context.Background()

	ids := security.NewUUIDv7Generator()
	userID, _ := ids.New()
	us.Create(ctx, store.User{ID: userID, Email: uniqueEmail(t), PasswordHash: "hash"})
	defer us.Delete(ctx, userID)

	for i := 1; i <= 3; i++ {
		attempts, err := us.IncrementFailedAttempts(ctx, userID)
		if err != nil {
			t.Fatalf("increment failed: %v", err)
		}
		if attempts != i {
			t.Errorf("expected %d failed attempts, got %d", i, attempts)
		}
	}

	until := time.Now().Add(15 * time.Minute)
	if err := us.LockAccount(ctx, userID, until); err != nil {
		t.Fatalf("lock failed: %v", err)
	}

	locked, _ := us.GetByID(ctx, userID)
	if locked.LockedUntil == nil {
		t.Fatal("expected LockedUntil to be set")
	}
	if locked.FailedAttempts != 3 {
		t.Errorf("expected 3 failed attempts persisted, got %d", locked.FailedAttempts)
	}

	if err := us.ResetFailedAttempts(ctx, userID); err != nil {
		t.Fatalf("reset failed: %v", err)
	}

	reset, _ := us.GetByID(ctx, userID)
	if reset.LockedUntil != nil {
		t.Error("expected LockedUntil to be cleared after reset")
	}
	if reset.FailedAttempts != 0 {
		t.Errorf("expected 0 failed attempts after reset, got %d", reset.FailedAttempts)
	}
}
