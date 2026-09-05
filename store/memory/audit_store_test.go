package memory

import (
	"context"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// seedAt places n events of one type at an exact instant. Record stamps
// every event with time.Now(), so reaching into the slice is the only
// way to put a row in the past — which is what an in-package test is
// for, and what every window assertion below needs.
func seedAt(s *AuditStore, at time.Time, eventType store.AuditEventType, n int) {
	for i := 0; i < n; i++ {
		s.events = append(s.events, store.AuditEvent{Type: eventType, CreatedAt: at})
	}
}

func TestAuditStore_CountByType(t *testing.T) {
	s := NewAuditStore()
	now := time.Now()
	seedAt(s, now.Add(-time.Hour), store.EventLoginSuccess, 3)
	seedAt(s, now.Add(-time.Hour), store.EventLoginFailed, 2)
	seedAt(s, now.Add(-time.Hour), store.EventAccountLocked, 1)

	counts, err := s.CountByType(context.Background(), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("CountByType: %v", err)
	}
	want := map[store.AuditEventType]int{
		store.EventLoginSuccess:  3,
		store.EventLoginFailed:   2,
		store.EventAccountLocked: 1,
	}
	for eventType, n := range want {
		if counts[eventType] != n {
			t.Errorf("%s = %d, want %d", eventType, counts[eventType], n)
		}
	}
	if len(counts) != len(want) {
		t.Errorf("got %d types, want %d: %v", len(counts), len(want), counts)
	}
}

// A type with no events in the window must be absent from the map, not
// present with a zero — the contract the digest relies on to tell
// "nothing happened" from "this type does not exist here".
func TestAuditStore_CountByType_OmitsTypesWithNoEvents(t *testing.T) {
	s := NewAuditStore()
	now := time.Now()
	seedAt(s, now.Add(-time.Minute), store.EventLoginSuccess, 1)

	counts, err := s.CountByType(context.Background(), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("CountByType: %v", err)
	}
	if _, present := counts[store.EventAccountLocked]; present {
		t.Errorf("account_locked is present with %d; a type with no events must be absent", counts[store.EventAccountLocked])
	}
}

func TestAuditStore_CountByType_ExcludesEventsBeforeSince(t *testing.T) {
	s := NewAuditStore()
	now := time.Now()
	seedAt(s, now.Add(-8*24*time.Hour), store.EventLoginSuccess, 5) // last week
	seedAt(s, now.Add(-2*time.Hour), store.EventLoginSuccess, 2)    // this week

	counts, err := s.CountByType(context.Background(), now.Add(-7*24*time.Hour))
	if err != nil {
		t.Fatalf("CountByType: %v", err)
	}
	if counts[store.EventLoginSuccess] != 2 {
		t.Errorf("login_success = %d, want 2 — the five older events are outside the window", counts[store.EventLoginSuccess])
	}
}

// "At or after since": an event recorded on the boundary instant is
// inside the window. Off by one here would silently drop the oldest
// events of every digest.
func TestAuditStore_CountByType_BoundaryIsInclusive(t *testing.T) {
	s := NewAuditStore()
	since := time.Now().Add(-time.Hour)
	seedAt(s, since, store.EventSignupSuccess, 1)
	seedAt(s, since.Add(-time.Nanosecond), store.EventSignupSuccess, 1)

	counts, err := s.CountByType(context.Background(), since)
	if err != nil {
		t.Fatalf("CountByType: %v", err)
	}
	if counts[store.EventSignupSuccess] != 1 {
		t.Errorf("signup_success = %d, want 1 — the boundary event counts, the one a nanosecond earlier does not", counts[store.EventSignupSuccess])
	}
}

func TestAuditStore_CountByType_EmptyWindowIsEmptyNonNilMap(t *testing.T) {
	s := NewAuditStore()
	seedAt(s, time.Now().Add(-48*time.Hour), store.EventLoginSuccess, 3)

	counts, err := s.CountByType(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("CountByType: %v", err)
	}
	if counts == nil {
		t.Fatal("counts is nil; an empty window must return an empty map")
	}
	if len(counts) != 0 {
		t.Errorf("counts = %v, want empty", counts)
	}
}

// A host writing its own event types into the same table gets them
// counted rather than dropped. Nothing here validates against the
// engine's own list of types, deliberately.
func TestAuditStore_CountByType_CountsUnknownTypes(t *testing.T) {
	s := NewAuditStore()
	seedAt(s, time.Now(), store.AuditEventType("acme_invoice_paid"), 4)

	counts, err := s.CountByType(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("CountByType: %v", err)
	}
	if counts["acme_invoice_paid"] != 4 {
		t.Errorf("acme_invoice_paid = %d, want 4", counts["acme_invoice_paid"])
	}
}

// The path a real caller takes: Record, then count. Record supplies its
// own timestamp, so this is the one case that does not touch s.events.
func TestAuditStore_CountByType_AfterRecord(t *testing.T) {
	s := NewAuditStore()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := s.Record(ctx, store.AuditEvent{Type: store.EventTokenRotated, UserID: "user-1"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	counts, err := s.CountByType(ctx, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatalf("CountByType: %v", err)
	}
	if counts[store.EventTokenRotated] != 3 {
		t.Errorf("token_rotated = %d, want 3", counts[store.EventTokenRotated])
	}
}
