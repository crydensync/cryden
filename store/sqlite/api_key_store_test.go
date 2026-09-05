package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

func seedAPIKey(t *testing.T, keys *APIKeyStore, key store.APIKey) store.APIKey {
	t.Helper()
	if err := keys.Create(context.Background(), key); err != nil {
		t.Fatalf("creating key %s: %v", key.ID, err)
	}
	return key
}

func TestAPIKeyStore_RoundTrip(t *testing.T) {
	db := newTestDB(t)
	keys := NewAPIKeyStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	created := time.Now().Add(-time.Hour).UTC().Truncate(time.Nanosecond)
	expires := created.Add(24 * time.Hour)
	seedAPIKey(t, keys, store.APIKey{
		ID:        "key-1",
		UserID:    "user-1",
		Name:      "ci deploy",
		Prefix:    "ck_9f3a1c02",
		KeyHash:   "hash-1",
		Scopes:    []string{"deploy:write", "logs:read"},
		ExpiresAt: &expires,
		CreatedAt: created,
	})

	got, err := keys.GetByKeyHash(ctx, "hash-1")
	if err != nil {
		t.Fatalf("GetByKeyHash: %v", err)
	}
	if got.ID != "key-1" || got.UserID != "user-1" || got.Name != "ci deploy" || got.Prefix != "ck_9f3a1c02" {
		t.Errorf("round trip lost a field: %+v", got)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "deploy:write" || got.Scopes[1] != "logs:read" {
		t.Errorf("scopes came back as %v", got.Scopes)
	}
	// The TEXT column keeps nanoseconds, which is the whole reason for
	// the fixed-width layout — a truncated timestamp would order rows
	// wrongly against each other.
	if !got.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, created)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, expires)
	}
	if got.LastUsedAt != nil || got.RevokedAt != nil {
		t.Errorf("a fresh key came back used or revoked: %+v", got)
	}
}

func TestAPIKeyStore_OptionalFieldsStayNull(t *testing.T) {
	db := newTestDB(t)
	keys := NewAPIKeyStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	// No name, no prefix, no scopes, no expiry, no CreatedAt: the store
	// assigns the timestamp and leaves the rest absent.
	seedAPIKey(t, keys, store.APIKey{ID: "key-1", UserID: "user-1", KeyHash: "hash-1"})

	got, err := keys.GetByKeyHash(ctx, "hash-1")
	if err != nil {
		t.Fatalf("GetByKeyHash: %v", err)
	}
	if got.Name != "" || got.Prefix != "" {
		t.Errorf("expected empty name and prefix, got %+v", got)
	}
	if got.Scopes != nil {
		t.Errorf("expected nil scopes, got %v", got.Scopes)
	}
	if got.ExpiresAt != nil {
		t.Errorf("expected no expiry, got %v", got.ExpiresAt)
	}
	if got.CreatedAt.IsZero() {
		t.Error("the store did not assign CreatedAt")
	}

	// An empty-but-not-nil scope list is a different statement and must
	// survive as one.
	seedAPIKey(t, keys, store.APIKey{ID: "key-2", UserID: "user-1", KeyHash: "hash-2", Scopes: []string{}})
	got2, err := keys.GetByKeyHash(ctx, "hash-2")
	if err != nil {
		t.Fatalf("GetByKeyHash: %v", err)
	}
	if got2.Scopes == nil || len(got2.Scopes) != 0 {
		t.Errorf("expected an empty non-nil scope list, got %v", got2.Scopes)
	}
}

func TestAPIKeyStore_GetByKeyHashUnknown(t *testing.T) {
	db := newTestDB(t)
	keys := NewAPIKeyStore(db)

	if _, err := keys.GetByKeyHash(context.Background(), "nothing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected store.ErrNotFound, got %v", err)
	}
}

func TestAPIKeyStore_ListByUserOrdersNewestFirst(t *testing.T) {
	db := newTestDB(t)
	keys := NewAPIKeyStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")
	seedUser(t, db, "user-2", "other+raymondproguy@dev.com")

	now := time.Now()
	seedAPIKey(t, keys, store.APIKey{ID: "old", UserID: "user-1", KeyHash: "h-old", CreatedAt: now.Add(-48 * time.Hour)})
	seedAPIKey(t, keys, store.APIKey{ID: "new", UserID: "user-1", KeyHash: "h-new", CreatedAt: now})
	seedAPIKey(t, keys, store.APIKey{ID: "mid", UserID: "user-1", KeyHash: "h-mid", CreatedAt: now.Add(-24 * time.Hour)})
	seedAPIKey(t, keys, store.APIKey{ID: "gone", UserID: "user-1", KeyHash: "h-gone", CreatedAt: now})
	seedAPIKey(t, keys, store.APIKey{ID: "theirs", UserID: "user-2", KeyHash: "h-theirs", CreatedAt: now})

	if err := keys.Revoke(ctx, "user-1", "gone"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	listed, err := keys.ListByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	var ids []string
	for _, k := range listed {
		ids = append(ids, k.ID)
	}
	if len(ids) != 3 || ids[0] != "new" || ids[1] != "mid" || ids[2] != "old" {
		t.Errorf("listed %v, want [new mid old]", ids)
	}
}

func TestAPIKeyStore_RevokeIsScopedAndOnlyOnce(t *testing.T) {
	db := newTestDB(t)
	keys := NewAPIKeyStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")
	seedUser(t, db, "user-2", "other+raymondproguy@dev.com")

	seedAPIKey(t, keys, store.APIKey{ID: "key-1", UserID: "user-1", KeyHash: "hash-1"})

	// Another user's revoke must not match the row.
	if err := keys.Revoke(ctx, "user-2", "key-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("foreign revoke: expected store.ErrNotFound, got %v", err)
	}
	got, _ := keys.GetByKeyHash(ctx, "hash-1")
	if got.RevokedAt != nil {
		t.Fatal("a foreign revoke marked the key revoked")
	}

	if err := keys.Revoke(ctx, "user-1", "key-1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	revoked, _ := keys.GetByKeyHash(ctx, "hash-1")
	if revoked.RevokedAt == nil {
		t.Fatal("Revoke did not set RevokedAt")
	}

	// The second one must not silently move the timestamp.
	if err := keys.Revoke(ctx, "user-1", "key-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second revoke: expected store.ErrNotFound, got %v", err)
	}
	again, _ := keys.GetByKeyHash(ctx, "hash-1")
	if !again.RevokedAt.Equal(*revoked.RevokedAt) {
		t.Errorf("RevokedAt moved: %v then %v", revoked.RevokedAt, again.RevokedAt)
	}
	// Revoked rows still come back from GetByKeyHash — telling
	// "revoked" from "unknown" is the auth layer's job.
	if again.ID != "key-1" {
		t.Error("a revoked key vanished from GetByKeyHash")
	}
}

func TestAPIKeyStore_TouchLastUsed(t *testing.T) {
	db := newTestDB(t)
	keys := NewAPIKeyStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	seedAPIKey(t, keys, store.APIKey{ID: "key-1", UserID: "user-1", KeyHash: "hash-1"})

	at := time.Now().UTC().Truncate(time.Nanosecond)
	if err := keys.TouchLastUsed(ctx, "key-1", at); err != nil {
		t.Fatalf("TouchLastUsed: %v", err)
	}
	got, _ := keys.GetByKeyHash(ctx, "hash-1")
	if got.LastUsedAt == nil || !got.LastUsedAt.Equal(at) {
		t.Errorf("LastUsedAt = %v, want %v", got.LastUsedAt, at)
	}

	// A key that no longer exists is not an error: the write is
	// best-effort by contract.
	if err := keys.TouchLastUsed(ctx, "no-such-key", at); err != nil {
		t.Errorf("touching a missing key returned %v, want nil", err)
	}
}

func TestAPIKeyStore_DeletingTheUserDeletesTheKeys(t *testing.T) {
	db := newTestDB(t)
	keys := NewAPIKeyStore(db)
	users := NewUserStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	seedAPIKey(t, keys, store.APIKey{ID: "key-1", UserID: "user-1", KeyHash: "hash-1"})

	if err := users.Delete(ctx, "user-1"); err != nil {
		t.Fatalf("deleting the user: %v", err)
	}
	// A key outliving its owner would authenticate as nobody.
	if _, err := keys.GetByKeyHash(ctx, "hash-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected the key to be gone, got %v", err)
	}
}
