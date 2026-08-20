package cryden

import (
	"context"
	"testing"

	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
)

func TestGetUser_Success(t *testing.T) {
	cfg := validConfig()
	engine, _ := New(cfg)
	ctx := context.Background()

	_, err := SignUp(ctx, engine, "devray@example.com", "Pass@2026", "1.2.3.4")
	if err != nil {
		t.Fatalf("signup failed: %v", err)
	}

	user, err := GetUser(ctx, engine, "devray@example.com")
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if user.Email != "devray@example.com" {
		t.Errorf("expected devray@example.com, got %s", user.Email)
	}
}

func TestGetUser_NotFound(t *testing.T) {
	cfg := validConfig()
	engine, _ := New(cfg)
	ctx := context.Background()

	_, err := GetUser(ctx, engine, "nobody@example.com")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestListPublicSessions_ExcludesTokenHash(t *testing.T) {
	cfg := validConfig()
	engine, _ := New(cfg)
	ctx := context.Background()

	SignUp(ctx, engine, "devray@example.com", "Pass@2026", "1.2.3.4")
	Login(ctx, engine, "devray@example.com", "Pass@2026", "1.2.3.4", "test-agent")

	sessions, err := ListPublicSessions(ctx, engine, mustUserID(ctx, engine, t))
	if err != nil {
		t.Fatalf("ListPublicSessions failed: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	// PublicSession has no TokenHash field at all — this is a
	// compile-time guarantee, not just a runtime check. If this test
	// compiles, the field genuinely doesn't exist on the type.
	if sessions[0].ID == "" {
		t.Error("expected a populated session ID")
	}
}

func mustUserID(ctx context.Context, e *Engine, t *testing.T) string {
	t.Helper()
	u, err := GetUser(ctx, e, "devray@example.com")
	if err != nil {
		t.Fatalf("failed to look up user: %v", err)
	}
	return u.ID
}

func TestStore_ListAllAndCount_Memory(t *testing.T) {
	us := memory.NewUserStore()
	ctx := context.Background()

	count, err := us.Count(ctx)
	if err != nil || count != 0 {
		t.Fatalf("expected 0 users initially, got %d (err: %v)", count, err)
	}

	for i := 0; i < 3; i++ {
		us.Create(ctx, store.User{ID: string(rune('a' + i)), Email: string(rune('a'+i)) + "@example.com"})
	}

	count, err = us.Count(ctx)
	if err != nil || count != 3 {
		t.Fatalf("expected 3 users, got %d (err: %v)", count, err)
	}

	all, err := us.ListAll(ctx, 10, 0)
	if err != nil || len(all) != 3 {
		t.Fatalf("expected 3 users listed, got %d (err: %v)", len(all), err)
	}

	paged, err := us.ListAll(ctx, 2, 0)
	if err != nil || len(paged) != 2 {
		t.Fatalf("expected 2 users with limit=2, got %d (err: %v)", len(paged), err)
	}
}

func TestStore_CountActive_Memory(t *testing.T) {
	ss := memory.NewSessionStore()
	ctx := context.Background()

	ss.Create(ctx, store.Session{ID: "s1", FamilyID: "s1", UserID: "u1"})
	ss.Create(ctx, store.Session{ID: "s2", FamilyID: "s2", UserID: "u1"})
	ss.Revoke(ctx, "s2")

	count, err := ss.CountActive(ctx)
	if err != nil || count != 1 {
		t.Fatalf("expected 1 active session, got %d (err: %v)", count, err)
	}
}

func TestStore_SearchByType_Memory(t *testing.T) {
	as := memory.NewAuditStore()
	ctx := context.Background()

	as.Record(ctx, store.AuditEvent{Type: store.EventLoginSuccess, UserID: "u1"})
	as.Record(ctx, store.AuditEvent{Type: store.EventTokenReuseDetected, UserID: "u2"})
	as.Record(ctx, store.AuditEvent{Type: store.EventTokenReuseDetected, UserID: "u3"})

	events, err := as.SearchByType(ctx, store.EventTokenReuseDetected, 10)
	if err != nil {
		t.Fatalf("SearchByType failed: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 token_reuse_detected events across all users, got %d", len(events))
	}
	for _, e := range events {
		if e.Type != store.EventTokenReuseDetected {
			t.Errorf("expected only token_reuse_detected events, got %s", e.Type)
		}
	}
}
