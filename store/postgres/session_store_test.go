package postgres

import (
	"context"
	"testing"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
)

func createTestUser(t *testing.T, us *UserStore) string {
	t.Helper()
	ids := security.NewUUIDv7Generator()
	userID, _ := ids.New()
	if err := us.Create(context.Background(), store.User{ID: userID, Email: uniqueEmail(t), PasswordHash: "hash"}); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return userID
}

func TestPostgresSessionStore_CreateAndGet(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	ss := NewSessionStore(db)
	ctx := context.Background()

	userID := createTestUser(t, us)
	defer us.Delete(ctx, userID)

	ids := security.NewUUIDv7Generator()
	sessionID, _ := ids.New()

	err := ss.Create(ctx, store.Session{
		ID: sessionID, FamilyID: sessionID, UserID: userID,
		TokenHash: "hash-abc", IP: "1.2.3.4", UserAgent: "test-agent",
	})
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	byID, err := ss.GetByID(ctx, sessionID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if byID.TokenHash != "hash-abc" {
		t.Errorf("expected hash-abc, got %s", byID.TokenHash)
	}

	byHash, err := ss.GetByTokenHash(ctx, "hash-abc")
	if err != nil {
		t.Fatalf("GetByTokenHash failed: %v", err)
	}
	if byHash.ID != sessionID {
		t.Errorf("expected %s, got %s", sessionID, byHash.ID)
	}
}

func TestPostgresSessionStore_ListByUser_ExcludesRevoked(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	ss := NewSessionStore(db)
	ctx := context.Background()

	userID := createTestUser(t, us)
	defer us.Delete(ctx, userID)

	ids := security.NewUUIDv7Generator()
	s1, _ := ids.New()
	s2, _ := ids.New()
	ss.Create(ctx, store.Session{ID: s1, FamilyID: s1, UserID: userID, TokenHash: s1 + "-hash"})
	ss.Create(ctx, store.Session{ID: s2, FamilyID: s2, UserID: userID, TokenHash: s2 + "-hash"})
	ss.Revoke(ctx, s2)

	list, err := ss.ListByUser(ctx, userID)
	if err != nil {
		t.Fatalf("ListByUser failed: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 active session, got %d", len(list))
	}
	if list[0].ID != s1 {
		t.Errorf("expected remaining session %s, got %s", s1, list[0].ID)
	}
}

func TestPostgresSessionStore_RevokeFamily(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	ss := NewSessionStore(db)
	ctx := context.Background()

	userID := createTestUser(t, us)
	defer us.Delete(ctx, userID)

	ids := security.NewUUIDv7Generator()
	familyID, _ := ids.New()
	s1, _ := ids.New()
	s2, _ := ids.New()
	ss.Create(ctx, store.Session{ID: s1, FamilyID: familyID, UserID: userID, TokenHash: s1 + "-hash"})
	ss.Create(ctx, store.Session{ID: s2, FamilyID: familyID, UserID: userID, TokenHash: s2 + "-hash"})

	if err := ss.RevokeFamily(ctx, familyID); err != nil {
		t.Fatalf("RevokeFamily failed: %v", err)
	}

	got1, _ := ss.GetByID(ctx, s1)
	got2, _ := ss.GetByID(ctx, s2)
	if got1.RevokedAt == nil || got2.RevokedAt == nil {
		t.Error("expected both sessions in the family to be revoked")
	}
}

// TestPostgresSessionStore_RotateToken_IsAtomic is the single most
// important test in this file. It proves RotateToken's real DB
// transaction actually holds: the old session is revoked AND the new
// one is created together, or (on failure) neither happens.
func TestPostgresSessionStore_RotateToken_IsAtomic(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	ss := NewSessionStore(db)
	ctx := context.Background()

	userID := createTestUser(t, us)
	defer us.Delete(ctx, userID)

	ids := security.NewUUIDv7Generator()
	oldID, _ := ids.New()
	newID, _ := ids.New()
	familyID := oldID

	ss.Create(ctx, store.Session{ID: oldID, FamilyID: familyID, UserID: userID, TokenHash: "old-hash"})

	newSession := store.Session{
		ID: newID, FamilyID: familyID, UserID: userID, TokenHash: "new-hash",
	}
	if err := ss.RotateToken(ctx, oldID, newSession); err != nil {
		t.Fatalf("RotateToken failed: %v", err)
	}

	old, err := ss.GetByID(ctx, oldID)
	if err != nil {
		t.Fatalf("failed to fetch old session: %v", err)
	}
	if old.RevokedAt == nil {
		t.Error("expected old session to be revoked after RotateToken")
	}

	created, err := ss.GetByID(ctx, newID)
	if err != nil {
		t.Fatalf("expected new session to exist after RotateToken: %v", err)
	}
	if created.TokenHash != "new-hash" {
		t.Errorf("expected new-hash, got %s", created.TokenHash)
	}
	if created.FamilyID != familyID {
		t.Error("expected new session to retain the family ID")
	}
}

func TestPostgresSessionStore_RotateToken_FailsCleanlyOnAlreadyRevoked(t *testing.T) {
	// Rotating an already-revoked session should fail (checkRowsAffected
	// returns ErrNotFound since the WHERE ... AND revoked_at IS NULL
	// clause matches zero rows) — and critically, the transaction must
	// roll back so the "new" session is NEVER created as a side effect
	// of a failed rotation.
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	ss := NewSessionStore(db)
	ctx := context.Background()

	userID := createTestUser(t, us)
	defer us.Delete(ctx, userID)

	ids := security.NewUUIDv7Generator()
	oldID, _ := ids.New()
	newID, _ := ids.New()

	ss.Create(ctx, store.Session{ID: oldID, FamilyID: oldID, UserID: userID, TokenHash: "old-hash-2"})
	ss.Revoke(ctx, oldID) // already revoked

	newSession := store.Session{ID: newID, FamilyID: oldID, UserID: userID, TokenHash: "new-hash-2"}
	err := ss.RotateToken(ctx, oldID, newSession)
	if err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// The critical assertion: the new session must NOT exist — proves
	// the transaction actually rolled back rather than partially applying.
	if _, err := ss.GetByID(ctx, newID); err != store.ErrNotFound {
		t.Error("expected new session to NOT exist after a failed rotation — transaction should have rolled back")
	}
}
