package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

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

// dbNow reads the database's own clock. Every timestamp in these two
// tests is derived from it rather than from time.Now(): created_at is
// written by Postgres, so a few milliseconds of skew between this
// process and the server would otherwise decide whether a row lands
// inside the window under test.
func dbNow(t *testing.T, db *sql.DB) time.Time {
	t.Helper()
	var now time.Time
	if err := db.QueryRow(`SELECT now()`).Scan(&now); err != nil {
		t.Fatalf("SELECT now(): %v", err)
	}
	return now
}

// seedAuditAt inserts rows with an explicit created_at, which Record
// cannot do — it always uses DEFAULT now(). Returns the IDs so the test
// can clean up after itself; audit rows outlive the user they belong to
// (ON DELETE SET NULL), so nothing else would remove them.
func seedAuditAt(t *testing.T, db *sql.DB, at time.Time, eventType store.AuditEventType, n int) []string {
	t.Helper()
	var ids []string
	for i := 0; i < n; i++ {
		var id string
		err := db.QueryRow(`
			INSERT INTO audit_events (id, type, user_id, ip, metadata, created_at)
			VALUES (gen_random_uuid(), $1, NULL, NULL, NULL, $2)
			RETURNING id
		`, string(eventType), at).Scan(&id)
		if err != nil {
			t.Fatalf("insert audit row: %v", err)
		}
		ids = append(ids, id)
	}
	return ids
}

func deleteAuditRows(t *testing.T, db *sql.DB, ids []string) {
	t.Helper()
	for _, id := range ids {
		if _, err := db.Exec(`DELETE FROM audit_events WHERE id = $1`, id); err != nil {
			t.Errorf("cleanup of audit row %s: %v", id, err)
		}
	}
}

// Counts are asserted as deltas against a baseline taken in the same
// window: this runs against a shared database that other tests in this
// package have already written audit rows into, and a digest's job is
// to count what is there, not to require an empty table.
func TestPostgresAuditStore_CountByType(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	as := NewAuditStore(db)
	ctx := context.Background()

	now := dbNow(t, db)
	since := now.Add(-24 * time.Hour)

	baseline, err := as.CountByType(ctx, since)
	if err != nil {
		t.Fatalf("CountByType (baseline): %v", err)
	}

	ids := seedAuditAt(t, db, now.Add(-time.Hour), store.EventLoginSuccess, 4)
	ids = append(ids, seedAuditAt(t, db, now.Add(-time.Hour), store.EventAccountLocked, 2)...)
	// A type the engine does not define, to prove nothing validates
	// against its own list on the way out.
	ids = append(ids, seedAuditAt(t, db, now.Add(-time.Hour), store.AuditEventType("acme_invoice_paid"), 3)...)
	defer deleteAuditRows(t, db, ids)

	counts, err := as.CountByType(ctx, since)
	if err != nil {
		t.Fatalf("CountByType: %v", err)
	}
	for _, tc := range []struct {
		eventType store.AuditEventType
		want      int
	}{
		{store.EventLoginSuccess, 4},
		{store.EventAccountLocked, 2},
		{store.AuditEventType("acme_invoice_paid"), 3},
	} {
		if got := counts[tc.eventType] - baseline[tc.eventType]; got != tc.want {
			t.Errorf("%s rose by %d, want %d", tc.eventType, got, tc.want)
		}
	}
}

// The window bound: at or after since. Rows before it do not count,
// a row exactly on it does.
func TestPostgresAuditStore_CountByType_WindowBounds(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	as := NewAuditStore(db)
	ctx := context.Background()

	now := dbNow(t, db)
	since := now.Add(-7 * 24 * time.Hour)

	baseline, err := as.CountByType(ctx, since)
	if err != nil {
		t.Fatalf("CountByType (baseline): %v", err)
	}

	eventType := store.AuditEventType("acme_window_probe")
	ids := seedAuditAt(t, db, since.Add(-time.Hour), eventType, 5) // before the window
	ids = append(ids, seedAuditAt(t, db, since, eventType, 1)...)  // exactly on it
	ids = append(ids, seedAuditAt(t, db, now.Add(-time.Minute), eventType, 2)...)
	defer deleteAuditRows(t, db, ids)

	counts, err := as.CountByType(ctx, since)
	if err != nil {
		t.Fatalf("CountByType: %v", err)
	}
	if got := counts[eventType] - baseline[eventType]; got != 3 {
		t.Errorf("%s rose by %d, want 3 — boundary inclusive, the five older rows excluded", eventType, got)
	}
}
