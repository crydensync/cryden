package session

import (
	"context"
	"testing"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
)

type noopLogger struct{}

func (noopLogger) Debug(msg string, fields map[string]string) {}
func (noopLogger) Info(msg string, fields map[string]string)  {}
func (noopLogger) Warn(msg string, fields map[string]string)  {}
func (noopLogger) Error(msg string, fields map[string]string) {}

var _ logger.Logger = noopLogger{}

func TestList_ReturnsOnlyActiveSessionsForUser(t *testing.T) {
	sessions := memory.NewSessionStore()
	ctx := context.Background()

	sessions.Create(ctx, store.Session{ID: "s1", FamilyID: "s1", UserID: "user-1"})
	sessions.Create(ctx, store.Session{ID: "s2", FamilyID: "s2", UserID: "user-1"})
	sessions.Create(ctx, store.Session{ID: "s3", FamilyID: "s3", UserID: "user-2"})
	sessions.Revoke(ctx, "s2")

	list, err := List(ctx, sessions, "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 active session for user-1, got %d", len(list))
	}
	if list[0].ID != "s1" {
		t.Errorf("expected remaining session to be s1, got %s", list[0].ID)
	}
}

func TestRevoke_RejectsOwnershipMismatch(t *testing.T) {
	sessions := memory.NewSessionStore()
	audit := memory.NewAuditStore()
	ctx := context.Background()

	sessions.Create(ctx, store.Session{ID: "s1", FamilyID: "s1", UserID: "victim"})

	err := Revoke(ctx, sessions, audit, noopLogger{}, "s1", "attacker")
	if err != store.ErrSessionNotOwned {
		t.Fatalf("expected ErrSessionNotOwned, got %v", err)
	}

	sess, _ := sessions.GetByID(ctx, "s1")
	if sess.RevokedAt != nil {
		t.Error("expected victim's session to remain active")
	}
}

func TestRevoke_Success(t *testing.T) {
	sessions := memory.NewSessionStore()
	audit := memory.NewAuditStore()
	ctx := context.Background()

	sessions.Create(ctx, store.Session{ID: "s1", FamilyID: "s1", UserID: "user-1"})

	if err := Revoke(ctx, sessions, audit, noopLogger{}, "s1", "user-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sess, _ := sessions.GetByID(ctx, "s1")
	if sess.RevokedAt == nil {
		t.Error("expected session to be revoked")
	}
}
