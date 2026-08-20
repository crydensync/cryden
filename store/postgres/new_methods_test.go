package postgres

import (
	"context"
	"testing"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
)

func TestPostgresUserStore_ListAllAndCount(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	ctx := context.Background()

	ids := security.NewUUIDv7Generator()
	var created []string
	for i := 0; i < 3; i++ {
		id, _ := ids.New()
		email := uniqueEmail(t)
		if err := us.Create(ctx, store.User{ID: id, Email: email, PasswordHash: "hash"}); err != nil {
			t.Fatalf("create failed: %v", err)
		}
		created = append(created, id)
	}
	defer func() {
		for _, id := range created {
			us.Delete(ctx, id)
		}
	}()

	all, err := us.ListAll(ctx, 1000, 0)
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}
	foundCount := 0
	for _, u := range all {
		for _, id := range created {
			if u.ID == id {
				foundCount++
			}
		}
	}
	if foundCount != 3 {
		t.Errorf("expected all 3 created users in ListAll results, found %d", foundCount)
	}

	limited, err := us.ListAll(ctx, 1, 0)
	if err != nil {
		t.Fatalf("ListAll with limit failed: %v", err)
	}
	if len(limited) != 1 {
		t.Errorf("expected exactly 1 result with limit=1, got %d", len(limited))
	}

	count, err := us.Count(ctx)
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count < 3 {
		t.Errorf("expected at least 3 users counted, got %d", count)
	}
}

func TestPostgresSessionStore_CountActive(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	ss := NewSessionStore(db)
	ctx := context.Background()

	userID := createTestUser(t, us)
	defer us.Delete(ctx, userID)

	before, err := ss.CountActive(ctx)
	if err != nil {
		t.Fatalf("CountActive failed: %v", err)
	}

	ids := security.NewUUIDv7Generator()
	s1, _ := ids.New()
	s2, _ := ids.New()
	ss.Create(ctx, store.Session{ID: s1, FamilyID: s1, UserID: userID, TokenHash: s1 + "-hash"})
	ss.Create(ctx, store.Session{ID: s2, FamilyID: s2, UserID: userID, TokenHash: s2 + "-hash"})
	ss.Revoke(ctx, s2) // one revoked, one still active

	after, err := ss.CountActive(ctx)
	if err != nil {
		t.Fatalf("CountActive failed: %v", err)
	}
	if after != before+1 {
		t.Errorf("expected active count to increase by exactly 1 (one created active, one created then revoked), got before=%d after=%d", before, after)
	}
}

func TestPostgresAuditStore_SearchByType(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	as := NewAuditStore(db)
	ctx := context.Background()

	user1 := createTestUser(t, us)
	defer us.Delete(ctx, user1)
	user2 := createTestUser(t, us)
	defer us.Delete(ctx, user2)

	as.Record(ctx, store.AuditEvent{Type: store.EventTokenReuseDetected, UserID: user1})
	as.Record(ctx, store.AuditEvent{Type: store.EventTokenReuseDetected, UserID: user2})
	as.Record(ctx, store.AuditEvent{Type: store.EventLoginSuccess, UserID: user1})

	events, err := as.SearchByType(ctx, store.EventTokenReuseDetected, 100)
	if err != nil {
		t.Fatalf("SearchByType failed: %v", err)
	}

	foundUser1, foundUser2 := false, false
	for _, e := range events {
		if e.Type != store.EventTokenReuseDetected {
			t.Errorf("expected only token_reuse_detected events, got %s", e.Type)
		}
		if e.UserID == user1 {
			foundUser1 = true
		}
		if e.UserID == user2 {
			foundUser2 = true
		}
	}
	if !foundUser1 || !foundUser2 {
		t.Error("expected search to find the event for BOTH users — this is the system-wide property that matters")
	}
}
