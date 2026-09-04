package memory

import (
	"context"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// The other memory stores are covered through the auth-layer tests that
// use them. This one gets its own: the empty-key guards, the window
// filter and the newest-first walk are real logic the detector's
// correctness depends on, and none of it is visible from auth.

func TestAnomalyStore_ListRecentSuccessesIsNewestFirstAndScoped(t *testing.T) {
	ctx := context.Background()
	s := NewAnomalyStore()

	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if err := s.RecordAttempt(ctx, store.LoginAttempt{
			UserID: "user-1", IP: ip, UserAgent: "test-agent", Outcome: store.OutcomeSuccess,
		}); err != nil {
			t.Fatalf("RecordAttempt failed: %v", err)
		}
	}
	// Noise that must not appear: another user's success, and this
	// user's failure.
	_ = s.RecordAttempt(ctx, store.LoginAttempt{UserID: "user-2", IP: "9.9.9.9", Outcome: store.OutcomeSuccess})
	_ = s.RecordAttempt(ctx, store.LoginAttempt{UserID: "user-1", IP: "8.8.8.8", Outcome: store.OutcomeFailure})

	got, err := s.ListRecentSuccesses(ctx, "user-1", 10)
	if err != nil {
		t.Fatalf("ListRecentSuccesses failed: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 successes for user-1, got %d", len(got))
	}
	if got[0].IP != "3.3.3.3" {
		t.Fatalf("expected newest first, got %s", got[0].IP)
	}
	if got[0].CreatedAt.IsZero() {
		t.Fatal("RecordAttempt should stamp CreatedAt")
	}
}

// A failure must never teach the baseline that an IP is familiar —
// otherwise an attacker self-trusts their own address by failing first.
func TestAnomalyStore_FailuresNeverEnterTheSuccessBaseline(t *testing.T) {
	ctx := context.Background()
	s := NewAnomalyStore()

	for i := 0; i < 5; i++ {
		_ = s.RecordAttempt(ctx, store.LoginAttempt{
			UserID: "user-1", IP: "6.6.6.6", UserAgent: "attacker-agent", Outcome: store.OutcomeFailure,
		})
	}

	got, err := s.ListRecentSuccesses(ctx, "user-1", 10)
	if err != nil {
		t.Fatalf("ListRecentSuccesses failed: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("failures must not appear as successes, got %d", len(got))
	}
}

func TestAnomalyStore_ListRecentSuccessesHonoursLimit(t *testing.T) {
	ctx := context.Background()
	s := NewAnomalyStore()

	for i := 0; i < 10; i++ {
		_ = s.RecordAttempt(ctx, store.LoginAttempt{UserID: "user-1", IP: "1.2.3.4", Outcome: store.OutcomeSuccess})
	}

	got, _ := s.ListRecentSuccesses(ctx, "user-1", 3)
	if len(got) != 3 {
		t.Fatalf("expected the limit to cap results at 3, got %d", len(got))
	}
}

func TestAnomalyStore_CountFailuresIsScopedAndWindowed(t *testing.T) {
	ctx := context.Background()
	s := NewAnomalyStore()

	// Two accounts targeted from one shared address, plus one success
	// that must not be counted as a failure.
	_ = s.RecordAttempt(ctx, store.LoginAttempt{UserID: "user-1", IP: "5.5.5.5", Outcome: store.OutcomeFailure})
	_ = s.RecordAttempt(ctx, store.LoginAttempt{UserID: "user-1", IP: "5.5.5.5", Outcome: store.OutcomeFailure})
	_ = s.RecordAttempt(ctx, store.LoginAttempt{UserID: "user-2", IP: "5.5.5.5", Outcome: store.OutcomeFailure})
	_ = s.RecordAttempt(ctx, store.LoginAttempt{UserID: "user-1", IP: "5.5.5.5", Outcome: store.OutcomeSuccess})

	since := time.Now().Add(-time.Minute)

	userCount, err := s.CountFailuresForUser(ctx, "user-1", since)
	if err != nil {
		t.Fatalf("CountFailuresForUser failed: %v", err)
	}
	if userCount != 2 {
		t.Fatalf("expected 2 failures for user-1, got %d", userCount)
	}

	// The per-IP count spans every account the address targeted, which
	// is the whole point of it being separate from the per-user count.
	ipCount, err := s.CountFailuresForIP(ctx, "5.5.5.5", since)
	if err != nil {
		t.Fatalf("CountFailuresForIP failed: %v", err)
	}
	if ipCount != 3 {
		t.Fatalf("expected 3 failures from 5.5.5.5 across accounts, got %d", ipCount)
	}

	// A window that opened after everything was recorded sees nothing.
	future := time.Now().Add(time.Minute)
	if n, _ := s.CountFailuresForUser(ctx, "user-1", future); n != 0 {
		t.Fatalf("expected the window to exclude older attempts, got %d", n)
	}
	if n, _ := s.CountFailuresForIP(ctx, "5.5.5.5", future); n != 0 {
		t.Fatalf("expected the window to exclude older attempts, got %d", n)
	}
}

// Failed logins for an unknown email carry no user ID. Without the
// empty-key guard, an empty userID would match every one of them and
// report the pile as a single account's history.
func TestAnomalyStore_EmptyKeysCountNothing(t *testing.T) {
	ctx := context.Background()
	s := NewAnomalyStore()

	for i := 0; i < 3; i++ {
		_ = s.RecordAttempt(ctx, store.LoginAttempt{IP: "", Outcome: store.OutcomeFailure})
	}

	since := time.Now().Add(-time.Minute)
	if n, _ := s.CountFailuresForUser(ctx, "", since); n != 0 {
		t.Fatalf("an empty userID must count nothing, got %d", n)
	}
	if n, _ := s.CountFailuresForIP(ctx, "", since); n != 0 {
		t.Fatalf("an empty IP must count nothing, got %d", n)
	}
}

func TestAnomalyStore_UnknownUserIsEmptyNotAnError(t *testing.T) {
	ctx := context.Background()
	s := NewAnomalyStore()

	got, err := s.ListRecentSuccesses(ctx, "nobody", 20)
	if err != nil {
		t.Fatalf("an unknown user should not be an error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no history for an unknown user, got %d", len(got))
	}
}
