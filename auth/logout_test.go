package auth

import (
	"context"
	"testing"

	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
)

func TestLogout_Success(t *testing.T) {
	sessions := memory.NewSessionStore()
	audit := memory.NewAuditStore()
	log := testLogger{}
	ctx := context.Background()

	sessions.Create(ctx, store.Session{ID: "sess-1", FamilyID: "sess-1", UserID: "user-1"})

	if err := Logout(ctx, sessions, audit, log, "sess-1", "user-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sess, _ := sessions.GetByID(ctx, "sess-1")
	if sess.RevokedAt == nil {
		t.Error("expected session to be revoked")
	}
}

func TestLogout_RejectsOwnershipMismatch(t *testing.T) {
	// Regression test: earlier in this build, Logout revoked ANY
	// session ID passed to it without checking it belonged to the
	// requesting user. This must never regress.
	sessions := memory.NewSessionStore()
	audit := memory.NewAuditStore()
	log := testLogger{}
	ctx := context.Background()

	sessions.Create(ctx, store.Session{ID: "sess-1", FamilyID: "sess-1", UserID: "victim-user"})

	err := Logout(ctx, sessions, audit, log, "sess-1", "attacker-user")
	if err != store.ErrSessionNotOwned {
		t.Fatalf("expected ErrSessionNotOwned, got %v", err)
	}

	// The victim's session must still be active — the attacker's
	// attempt must not have revoked it as a side effect.
	sess, _ := sessions.GetByID(ctx, "sess-1")
	if sess.RevokedAt != nil {
		t.Error("expected victim's session to remain active after a rejected ownership-mismatch logout attempt")
	}
}

func TestLogoutAll_RevokesOnlyThatUsersSessions(t *testing.T) {
	sessions := memory.NewSessionStore()
	audit := memory.NewAuditStore()
	log := testLogger{}
	ctx := context.Background()

	sessions.Create(ctx, store.Session{ID: "sess-1", FamilyID: "sess-1", UserID: "user-1"})
	sessions.Create(ctx, store.Session{ID: "sess-2", FamilyID: "sess-2", UserID: "user-1"})
	sessions.Create(ctx, store.Session{ID: "sess-3", FamilyID: "sess-3", UserID: "user-2"})

	if err := LogoutAll(ctx, sessions, audit, log, "user-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s1, _ := sessions.GetByID(ctx, "sess-1")
	s2, _ := sessions.GetByID(ctx, "sess-2")
	s3, _ := sessions.GetByID(ctx, "sess-3")

	if s1.RevokedAt == nil || s2.RevokedAt == nil {
		t.Error("expected both of user-1's sessions to be revoked")
	}
	if s3.RevokedAt != nil {
		t.Error("expected user-2's session to remain untouched by user-1's LogoutAll")
	}
}
