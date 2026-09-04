package memory

import (
	"context"
	"sync"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// AnomalyStore is an in-memory store.AnomalyStore implementation for
// tests and local experimentation only — not a supported production
// backend. Beyond the usual "it forgets everything on restart," an
// in-memory anomaly history is actively misleading in production: two
// instances would each hold half the evidence and neither would see the
// pattern. The Postgres implementation is authoritative for prod.
type AnomalyStore struct {
	mu       sync.Mutex
	attempts []store.LoginAttempt
}

func NewAnomalyStore() *AnomalyStore {
	return &AnomalyStore{}
}

func (s *AnomalyStore) RecordAttempt(ctx context.Context, attempt store.LoginAttempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	attempt.CreatedAt = time.Now()
	s.attempts = append(s.attempts, attempt)
	return nil
}

func (s *AnomalyStore) ListRecentSuccesses(ctx context.Context, userID string, limit int) ([]store.LoginAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.LoginAttempt
	for i := len(s.attempts) - 1; i >= 0 && len(out) < limit; i-- {
		a := s.attempts[i]
		if a.UserID == userID && a.Outcome == store.OutcomeSuccess {
			out = append(out, a)
		}
	}
	return out, nil
}

func (s *AnomalyStore) CountFailuresForUser(ctx context.Context, userID string, since time.Time) (int, error) {
	// An empty userID would otherwise match every unknown-email failure
	// ever recorded and report them as one user's history.
	if userID == "" {
		return 0, nil
	}
	return s.countFailures(func(a store.LoginAttempt) bool { return a.UserID == userID }, since), nil
}

func (s *AnomalyStore) CountFailuresForIP(ctx context.Context, ip string, since time.Time) (int, error) {
	if ip == "" {
		return 0, nil
	}
	return s.countFailures(func(a store.LoginAttempt) bool { return a.IP == ip }, since), nil
}

func (s *AnomalyStore) countFailures(match func(store.LoginAttempt) bool, since time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, a := range s.attempts {
		if a.Outcome != store.OutcomeFailure || a.CreatedAt.Before(since) {
			continue
		}
		if match(a) {
			count++
		}
	}
	return count
}

var _ store.AnomalyStore = (*AnomalyStore)(nil)
