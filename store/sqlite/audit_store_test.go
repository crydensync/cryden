package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

func TestAuditStore_RecordAssignsIDAndTimestamp(t *testing.T) {
	db := newTestDB(t)
	audit := NewAuditStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if err := audit.Record(ctx, store.AuditEvent{
		Type: store.EventLoginSuccess, UserID: "user-1", IP: "1.2.3.4",
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	events, err := audit.ListByUser(ctx, "user-1", 10)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	e := events[0]
	// Postgres gets these from gen_random_uuid() and DEFAULT now();
	// here they come from Go, so an empty ID or zero time means the
	// translation dropped them.
	if e.ID == "" {
		t.Error("ID is empty; the store must generate one")
	}
	if e.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero; the store must assign one")
	}
	if e.Type != store.EventLoginSuccess || e.IP != "1.2.3.4" {
		t.Errorf("wrong row back: %+v", e)
	}
	if e.Metadata != nil {
		t.Errorf("Metadata = %v, want nil when none was supplied", e.Metadata)
	}
}

// Metadata is JSONB in Postgres and JSON-in-TEXT here, so the round trip
// is the part worth checking: the anomaly and credential-stuffing
// features both put their signal codes in here, and a map that comes
// back empty loses the entire finding.
func TestAuditStore_MetadataRoundTrips(t *testing.T) {
	db := newTestDB(t)
	audit := NewAuditStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	want := map[string]string{"signals": "new_ip,new_device", "reason": "wrong_password"}
	if err := audit.Record(ctx, store.AuditEvent{
		Type: store.EventLoginFailed, UserID: "user-1", IP: "1.2.3.4", Metadata: want,
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	events, err := audit.ListByUser(ctx, "user-1", 10)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	got := events[0].Metadata
	if len(got) != len(want) {
		t.Fatalf("Metadata = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("Metadata[%q] = %q, want %q", k, got[k], v)
		}
	}

	// Stored as real JSON text, not a Go map's fmt output — SQLite's own
	// json_* functions have to be able to read it.
	var raw string
	if err := db.QueryRowContext(ctx, `SELECT metadata FROM audit_events`).Scan(&raw); err != nil {
		t.Fatalf("reading raw metadata: %v", err)
	}
	var valid int
	if err := db.QueryRowContext(ctx, `SELECT json_valid(?)`, raw).Scan(&valid); err != nil {
		t.Fatalf("json_valid: %v", err)
	}
	if valid != 1 {
		t.Errorf("stored metadata is not valid JSON: %s", raw)
	}
}

// A login_failed event for an unrecognised email has no user. Storing ""
// would both break the foreign key and make the row look attributable to
// a user whose ID happens to be empty.
func TestAuditStore_EmptyUserIDBecomesNull(t *testing.T) {
	db := newTestDB(t)
	audit := NewAuditStore(db)
	ctx := context.Background()

	if err := audit.Record(ctx, store.AuditEvent{
		Type: store.EventLoginFailed, IP: "9.9.9.9",
		Metadata: map[string]string{"reason": "no_such_user"},
	}); err != nil {
		t.Fatalf("Record with no user: %v", err)
	}

	var nulls int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_events WHERE user_id IS NULL`).Scan(&nulls); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if nulls != 1 {
		t.Fatalf("%d rows with a NULL user_id, want 1", nulls)
	}

	// And it must still come back out as "" rather than blowing up the
	// scan, which is what sql.NullString on the read side is for.
	events, err := audit.SearchByType(ctx, store.EventLoginFailed, 10)
	if err != nil {
		t.Fatalf("SearchByType: %v", err)
	}
	if len(events) != 1 || events[0].UserID != "" {
		t.Errorf("got %+v; want one event with an empty UserID", events)
	}
}

func TestAuditStore_ListByUserIsNewestFirstAndLimited(t *testing.T) {
	db := newTestDB(t)
	audit := NewAuditStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")
	seedUser(t, db, "user-2", "other@dev.com")

	for i := 0; i < 4; i++ {
		if err := audit.Record(ctx, store.AuditEvent{
			Type: store.EventLoginSuccess, UserID: "user-1",
			Metadata: map[string]string{"n": string(rune('0' + i))},
		}); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
		time.Sleep(time.Millisecond)
	}
	if err := audit.Record(ctx, store.AuditEvent{Type: store.EventLoginSuccess, UserID: "user-2"}); err != nil {
		t.Fatalf("Record for user-2: %v", err)
	}

	events, err := audit.ListByUser(ctx, "user-1", 2)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("limit 2 returned %d events", len(events))
	}
	if events[0].Metadata["n"] != "3" || events[1].Metadata["n"] != "2" {
		t.Errorf("got n=%q,%q; want the two newest, 3 then 2",
			events[0].Metadata["n"], events[1].Metadata["n"])
	}
	for _, e := range events {
		if e.UserID != "user-1" {
			t.Errorf("another user's event leaked in: %+v", e)
		}
	}
}

// SearchByType crosses users on purpose — "every token_reuse_detected
// event, whoever it happened to" is the query it exists for.
func TestAuditStore_SearchByTypeCrossesUsers(t *testing.T) {
	db := newTestDB(t)
	audit := NewAuditStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")
	seedUser(t, db, "user-2", "other@dev.com")

	for _, userID := range []string{"user-1", "user-2"} {
		if err := audit.Record(ctx, store.AuditEvent{Type: store.EventTokenReuseDetected, UserID: userID}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := audit.Record(ctx, store.AuditEvent{Type: store.EventLoginSuccess, UserID: "user-1"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	found, err := audit.SearchByType(ctx, store.EventTokenReuseDetected, 10)
	if err != nil {
		t.Fatalf("SearchByType: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("got %d events, want 2 across both users", len(found))
	}
	for _, e := range found {
		if e.Type != store.EventTokenReuseDetected {
			t.Errorf("wrong type came back: %+v", e)
		}
	}

	if none, err := audit.SearchByType(ctx, store.EventAccountLocked, 10); err != nil || len(none) != 0 {
		t.Errorf("SearchByType for an unused type: %d rows, %v", len(none), err)
	}
}
