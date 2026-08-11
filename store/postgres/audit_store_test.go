package postgres

import (
	"context"
	"testing"

	"github.com/crydensync/cryden/v2/store"
)

func TestPostgresAuditStore_RecordAndListByUser(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	as := NewAuditStore(db)
	ctx := context.Background()

	userID := createTestUser(t, us)
	defer us.Delete(ctx, userID)

	err := as.Record(ctx, store.AuditEvent{
		Type:     store.EventLoginSuccess,
		UserID:   userID,
		IP:       "1.2.3.4",
		Metadata: map[string]string{"reason": "test"},
	})
	if err != nil {
		t.Fatalf("record failed: %v", err)
	}

	events, err := as.ListByUser(ctx, userID, 10)
	if err != nil {
		t.Fatalf("ListByUser failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != store.EventLoginSuccess {
		t.Errorf("expected EventLoginSuccess, got %s", events[0].Type)
	}
	if events[0].Metadata["reason"] != "test" {
		t.Errorf("expected metadata reason=test, got %v", events[0].Metadata)
	}
}

// TestPostgresAuditStore_NullableUserID is the property that matters
// most here: a login_failed event for a nonexistent email has no real
// user to attribute to. An empty string UserID must persist as a real
// SQL NULL, not fail the insert (which would happen if it were passed
// as a literal empty-string UUID) and not silently become some other
// value.
func TestPostgresAuditStore_NullableUserID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	as := NewAuditStore(db)
	ctx := context.Background()

	err := as.Record(ctx, store.AuditEvent{
		Type: store.EventLoginFailed,
		// UserID deliberately empty — simulates "no such user" failure.
		IP:       "9.9.9.9",
		Metadata: map[string]string{"reason": "no_such_user"},
	})
	if err != nil {
		t.Fatalf("expected insert with empty UserID to succeed via NULL, got error: %v", err)
	}
}

func TestPostgresAuditStore_ListByUser_RespectsLimit(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	us := NewUserStore(db)
	as := NewAuditStore(db)
	ctx := context.Background()

	userID := createTestUser(t, us)
	defer us.Delete(ctx, userID)

	for i := 0; i < 5; i++ {
		as.Record(ctx, store.AuditEvent{Type: store.EventLoginSuccess, UserID: userID})
	}

	events, err := as.ListByUser(ctx, userID, 3)
	if err != nil {
		t.Fatalf("ListByUser failed: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("expected limit of 3 to be respected, got %d events", len(events))
	}
}
