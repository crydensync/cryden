package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

func TestAnomalyStore_RecordAttemptAssignsIDAndTimestamp(t *testing.T) {
	db := newTestDB(t)
	anomalies := NewAnomalyStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if err := anomalies.RecordAttempt(ctx, store.LoginAttempt{
		UserID: "user-1", IP: "1.2.3.4", UserAgent: "test-agent", Outcome: store.OutcomeSuccess,
	}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}

	got, err := anomalies.ListRecentSuccesses(ctx, "user-1", 10)
	if err != nil {
		t.Fatalf("ListRecentSuccesses: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d attempts, want 1", len(got))
	}
	// The interface says implementations assign these; Postgres uses
	// gen_random_uuid() and DEFAULT now(), here they come from Go.
	if got[0].ID == "" {
		t.Error("ID is empty; the store must generate one")
	}
	if got[0].CreatedAt.IsZero() {
		t.Error("CreatedAt is zero; the store must assign one")
	}
	if got[0].IP != "1.2.3.4" || got[0].UserAgent != "test-agent" {
		t.Errorf("wrong row back: %+v", got[0])
	}
}

// Successes only. A failed attempt teaching the baseline that an
// attacker's IP is familiar would defeat new-IP detection outright.
func TestAnomalyStore_ListRecentSuccessesExcludesFailures(t *testing.T) {
	db := newTestDB(t)
	anomalies := NewAnomalyStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")
	seedUser(t, db, "user-2", "other@dev.com")

	record := func(userID, ip string, outcome store.LoginAttemptOutcome) {
		t.Helper()
		if err := anomalies.RecordAttempt(ctx, store.LoginAttempt{
			UserID: userID, IP: ip, UserAgent: "agent", Outcome: outcome,
		}); err != nil {
			t.Fatalf("RecordAttempt: %v", err)
		}
		time.Sleep(time.Millisecond)
	}

	record("user-1", "1.1.1.1", store.OutcomeSuccess)
	record("user-1", "6.6.6.6", store.OutcomeFailure)
	record("user-1", "2.2.2.2", store.OutcomeSuccess)
	record("user-2", "3.3.3.3", store.OutcomeSuccess)

	got, err := anomalies.ListRecentSuccesses(ctx, "user-1", 10)
	if err != nil {
		t.Fatalf("ListRecentSuccesses: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d attempts, want 2 successes", len(got))
	}
	// Newest first.
	if got[0].IP != "2.2.2.2" || got[1].IP != "1.1.1.1" {
		t.Errorf("order = %s, %s; want 2.2.2.2 then 1.1.1.1", got[0].IP, got[1].IP)
	}
	for _, a := range got {
		if a.Outcome != store.OutcomeSuccess {
			t.Errorf("a failure leaked into the baseline: %+v", a)
		}
		if a.UserID != "user-1" {
			t.Errorf("another user's attempt leaked in: %+v", a)
		}
	}

	limited, err := anomalies.ListRecentSuccesses(ctx, "user-1", 1)
	if err != nil {
		t.Fatalf("ListRecentSuccesses with limit 1: %v", err)
	}
	if len(limited) != 1 || limited[0].IP != "2.2.2.2" {
		t.Errorf("limit 1 returned %+v", limited)
	}
}

// The since comparison is a string comparison on fixed-width TEXT. If
// the format ever loses its zero-padding, this is the test that breaks:
// an attempt inside the window would sort outside it.
func TestAnomalyStore_CountFailuresRespectsTheWindow(t *testing.T) {
	db := newTestDB(t)
	anomalies := NewAnomalyStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	for i := 0; i < 3; i++ {
		if err := anomalies.RecordAttempt(ctx, store.LoginAttempt{
			UserID: "user-1", IP: "9.9.9.9", Outcome: store.OutcomeFailure,
		}); err != nil {
			t.Fatalf("RecordAttempt: %v", err)
		}
	}
	if err := anomalies.RecordAttempt(ctx, store.LoginAttempt{
		UserID: "user-1", IP: "9.9.9.9", Outcome: store.OutcomeSuccess,
	}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}

	recent := time.Now().Add(-time.Minute)
	if n, err := anomalies.CountFailuresForUser(ctx, "user-1", recent); err != nil || n != 3 {
		t.Errorf("CountFailuresForUser = %d, %v; want 3 (the success must not count)", n, err)
	}
	if n, err := anomalies.CountFailuresForIP(ctx, "9.9.9.9", recent); err != nil || n != 3 {
		t.Errorf("CountFailuresForIP = %d, %v; want 3", n, err)
	}

	// A window that starts after everything happened must see nothing.
	future := time.Now().Add(time.Minute)
	if n, err := anomalies.CountFailuresForUser(ctx, "user-1", future); err != nil || n != 0 {
		t.Errorf("CountFailuresForUser with a future window = %d, %v; want 0", n, err)
	}
	if n, err := anomalies.CountFailuresForIP(ctx, "9.9.9.9", future); err != nil || n != 0 {
		t.Errorf("CountFailuresForIP with a future window = %d, %v; want 0", n, err)
	}
}

// Empty identifiers short-circuit rather than querying — the interface
// says so, and the alternative is a scan that matches whatever rows
// happen to have an empty column.
func TestAnomalyStore_EmptyIdentifiersReturnZero(t *testing.T) {
	db := newTestDB(t)
	anomalies := NewAnomalyStore(db)
	ctx := context.Background()

	// An attempt with no user and no IP, so a query that did run would
	// have something to match.
	if err := anomalies.RecordAttempt(ctx, store.LoginAttempt{Outcome: store.OutcomeFailure}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}

	since := time.Now().Add(-time.Hour)
	if n, err := anomalies.CountFailuresForUser(ctx, "", since); err != nil || n != 0 {
		t.Errorf("CountFailuresForUser(\"\") = %d, %v; want 0", n, err)
	}
	if n, err := anomalies.CountFailuresForIP(ctx, "", since); err != nil || n != 0 {
		t.Errorf("CountFailuresForIP(\"\") = %d, %v; want 0", n, err)
	}
	counts, err := anomalies.CountTargetsForIP(ctx, "", since)
	if err != nil || counts != (store.IPTargetCounts{}) {
		t.Errorf("CountTargetsForIP(\"\") = %+v, %v; want a zero value", counts, err)
	}
}

// CountTargetsForIP is the credential-stuffing query, and the one place
// Postgres's COUNT(*) FILTER had to become COUNT(CASE WHEN ...). The
// two numbers count different things and must not be conflated: known
// accounts are de-duplicated, unknown targets are not, because the
// attempted address is deliberately never stored.
func TestAnomalyStore_CountTargetsForIPSeparatesKnownFromUnknown(t *testing.T) {
	db := newTestDB(t)
	anomalies := NewAnomalyStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")
	seedUser(t, db, "user-2", "other@dev.com")
	seedUser(t, db, "user-3", "third@dev.com")

	record := func(userID string, outcome store.LoginAttemptOutcome) {
		t.Helper()
		if err := anomalies.RecordAttempt(ctx, store.LoginAttempt{
			UserID: userID, IP: "9.9.9.9", Outcome: outcome,
		}); err != nil {
			t.Fatalf("RecordAttempt: %v", err)
		}
	}

	// A spray: three real accounts, one of them hit twice, plus four
	// swings at addresses that match no account.
	record("user-1", store.OutcomeFailure)
	record("user-1", store.OutcomeFailure)
	record("user-2", store.OutcomeFailure)
	record("user-3", store.OutcomeFailure)
	for i := 0; i < 4; i++ {
		record("", store.OutcomeFailure)
	}
	// Neither a success nor another IP belongs in the counts.
	record("user-1", store.OutcomeSuccess)
	if err := anomalies.RecordAttempt(ctx, store.LoginAttempt{
		UserID: "user-2", IP: "8.8.8.8", Outcome: store.OutcomeFailure,
	}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}

	counts, err := anomalies.CountTargetsForIP(ctx, "9.9.9.9", time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatalf("CountTargetsForIP: %v", err)
	}
	if counts.DistinctAccounts != 3 {
		t.Errorf("DistinctAccounts = %d, want 3 — distinct accounts, not attempts", counts.DistinctAccounts)
	}
	if counts.UnknownTargetFailures != 4 {
		t.Errorf("UnknownTargetFailures = %d, want 4 — attempts, not distinct addresses", counts.UnknownTargetFailures)
	}

	// COUNT, not SUM: with no matching rows the unknown count must be 0,
	// not a NULL that fails to scan into an int.
	quiet, err := anomalies.CountTargetsForIP(ctx, "5.5.5.5", time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatalf("CountTargetsForIP for an unseen IP: %v", err)
	}
	if quiet != (store.IPTargetCounts{}) {
		t.Errorf("got %+v for an IP with no rows, want a zero value", quiet)
	}
}

// One account hammered many times is per-account lockout's job, not
// stuffing's — breadth must stay at 1 however high the count goes.
func TestAnomalyStore_ManyFailuresAgainstOneAccountIsNotBreadth(t *testing.T) {
	db := newTestDB(t)
	anomalies := NewAnomalyStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	for i := 0; i < 12; i++ {
		if err := anomalies.RecordAttempt(ctx, store.LoginAttempt{
			UserID: "user-1", IP: "9.9.9.9", Outcome: store.OutcomeFailure,
		}); err != nil {
			t.Fatalf("RecordAttempt: %v", err)
		}
	}

	counts, err := anomalies.CountTargetsForIP(ctx, "9.9.9.9", time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatalf("CountTargetsForIP: %v", err)
	}
	if counts.DistinctAccounts != 1 || counts.UnknownTargetFailures != 0 {
		t.Errorf("got %+v, want exactly one distinct account and no unknown targets", counts)
	}
	if n, err := anomalies.CountFailuresForIP(ctx, "9.9.9.9", time.Now().Add(-time.Minute)); err != nil || n != 12 {
		t.Errorf("CountFailuresForIP = %d, %v; want all 12 — volume is still visible", n, err)
	}
}
