package sqlite

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/crydensync/cryden/v2/store"
)

func codes(hashes ...string) []store.RecoveryCode {
	out := make([]store.RecoveryCode, 0, len(hashes))
	for _, h := range hashes {
		out = append(out, store.RecoveryCode{CodeHash: h})
	}
	return out
}

func TestRecoveryCodeStore_ReplaceAllInvalidatesThePreviousBatch(t *testing.T) {
	db := newTestDB(t)
	recovery := NewRecoveryCodeStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if err := recovery.ReplaceAll(ctx, "user-1", codes("old-1", "old-2", "old-3")); err != nil {
		t.Fatalf("first ReplaceAll: %v", err)
	}
	if n, err := recovery.CountUnused(ctx, "user-1"); err != nil || n != 3 {
		t.Fatalf("CountUnused = %d, %v; want 3", n, err)
	}

	if err := recovery.ReplaceAll(ctx, "user-1", codes("new-1", "new-2")); err != nil {
		t.Fatalf("second ReplaceAll: %v", err)
	}
	if n, err := recovery.CountUnused(ctx, "user-1"); err != nil || n != 2 {
		t.Fatalf("CountUnused = %d, %v; want 2", n, err)
	}
	// Regenerating always invalidates every previous code — a printed
	// sheet the user has replaced must stop working.
	if err := recovery.Consume(ctx, "user-1", "old-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("an old code still works: got %v, want store.ErrNotFound", err)
	}
	if err := recovery.Consume(ctx, "user-1", "new-1"); err != nil {
		t.Errorf("a new code does not work: %v", err)
	}
}

// ReplaceAll's transaction is the point: a crash between the delete and
// the inserts would leave an account with 2FA on and no recovery codes
// at all. A duplicate hash makes the insert fail partway through.
func TestRecoveryCodeStore_ReplaceAllRollsBackOnFailure(t *testing.T) {
	db := newTestDB(t)
	recovery := NewRecoveryCodeStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")
	seedUser(t, db, "user-2", "other@dev.com")

	if err := recovery.ReplaceAll(ctx, "user-1", codes("keep-1", "keep-2")); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	// code_hash is the primary key, globally — so a hash already held by
	// another user collides.
	if err := recovery.ReplaceAll(ctx, "user-2", codes("taken")); err != nil {
		t.Fatalf("seeding user-2: %v", err)
	}

	err := recovery.ReplaceAll(ctx, "user-1", codes("fresh-1", "taken", "fresh-2"))
	if err == nil {
		t.Fatal("ReplaceAll succeeded with a colliding hash")
	}

	// The original batch must survive intact.
	if n, err := recovery.CountUnused(ctx, "user-1"); err != nil || n != 2 {
		t.Fatalf("CountUnused after the failed replace = %d, %v; want the original 2", n, err)
	}
	if err := recovery.Consume(ctx, "user-1", "keep-1"); err != nil {
		t.Errorf("an original code stopped working after a rolled-back replace: %v", err)
	}
	if err := recovery.Consume(ctx, "user-1", "fresh-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a partially-inserted code survived: got %v, want store.ErrNotFound", err)
	}
}

func TestRecoveryCodeStore_ConsumeIsSingleUseAndScoped(t *testing.T) {
	db := newTestDB(t)
	recovery := NewRecoveryCodeStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")
	seedUser(t, db, "user-2", "other@dev.com")

	if err := recovery.ReplaceAll(ctx, "user-1", codes("code-1", "code-2")); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}

	if err := recovery.Consume(ctx, "user-1", "code-1"); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	// The same code must never validate twice.
	if err := recovery.Consume(ctx, "user-1", "code-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second Consume of the same code: got %v, want store.ErrNotFound", err)
	}
	if n, err := recovery.CountUnused(ctx, "user-1"); err != nil || n != 1 {
		t.Errorf("CountUnused = %d, %v; want 1 remaining", n, err)
	}

	// Every failure looks the same to the caller: wrong code,
	// already-used code, and no codes at all.
	if err := recovery.Consume(ctx, "user-1", "not-a-code"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("wrong code: got %v, want store.ErrNotFound", err)
	}
	if err := recovery.Consume(ctx, "user-2", "code-2"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another user's code: got %v, want store.ErrNotFound", err)
	}
	if err := recovery.Consume(ctx, "nobody", "code-2"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a user with no codes: got %v, want store.ErrNotFound", err)
	}
}

func TestRecoveryCodeStore_CountUnusedAndDeleteAll(t *testing.T) {
	db := newTestDB(t)
	recovery := NewRecoveryCodeStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if n, err := recovery.CountUnused(ctx, "user-1"); err != nil || n != 0 {
		t.Fatalf("CountUnused with no codes: %d, %v", n, err)
	}

	batch := make([]store.RecoveryCode, 0, 10)
	for i := 0; i < 10; i++ {
		batch = append(batch, store.RecoveryCode{CodeHash: fmt.Sprintf("code-%d", i)})
	}
	if err := recovery.ReplaceAll(ctx, "user-1", batch); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	for i := 0; i < 4; i++ {
		if err := recovery.Consume(ctx, "user-1", fmt.Sprintf("code-%d", i)); err != nil {
			t.Fatalf("Consume %d: %v", i, err)
		}
	}
	if n, err := recovery.CountUnused(ctx, "user-1"); err != nil || n != 6 {
		t.Errorf("CountUnused = %d, %v; want 6", n, err)
	}

	if err := recovery.DeleteAll(ctx, "user-1"); err != nil {
		t.Fatalf("DeleteAll: %v", err)
	}
	if n, err := recovery.CountUnused(ctx, "user-1"); err != nil || n != 0 {
		t.Errorf("CountUnused after DeleteAll = %d, %v", n, err)
	}
	// Hygiene, not a lookup: already clean is the desired end state.
	if err := recovery.DeleteAll(ctx, "user-1"); err != nil {
		t.Errorf("second DeleteAll: %v", err)
	}
	if err := recovery.DeleteAll(ctx, "nobody"); err != nil {
		t.Errorf("DeleteAll for an unknown user: %v", err)
	}
}

// An empty batch is a legitimate call — it is how a host wipes the codes
// through the same path that writes them.
func TestRecoveryCodeStore_ReplaceAllWithNoCodes(t *testing.T) {
	db := newTestDB(t)
	recovery := NewRecoveryCodeStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if err := recovery.ReplaceAll(ctx, "user-1", codes("code-1")); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	if err := recovery.ReplaceAll(ctx, "user-1", nil); err != nil {
		t.Fatalf("ReplaceAll with nil: %v", err)
	}
	if n, err := recovery.CountUnused(ctx, "user-1"); err != nil || n != 0 {
		t.Errorf("CountUnused = %d, %v; want 0", n, err)
	}
}
