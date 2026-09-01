package memory

import (
	"context"
	"sync"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// RecoveryCodeStore is an in-memory store.RecoveryCodeStore
// implementation for tests and local experimentation only — not a
// supported production backend. The Postgres implementation is
// authoritative for prod.
type RecoveryCodeStore struct {
	mu       sync.Mutex
	byUserID map[string][]store.RecoveryCode
}

func NewRecoveryCodeStore() *RecoveryCodeStore {
	return &RecoveryCodeStore{byUserID: make(map[string][]store.RecoveryCode)}
}

func (s *RecoveryCodeStore) ReplaceAll(ctx context.Context, userID string, codes []store.RecoveryCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	stored := make([]store.RecoveryCode, len(codes))
	for i, c := range codes {
		c.UserID = userID
		c.CreatedAt = now
		c.UsedAt = nil
		stored[i] = c
	}
	s.byUserID[userID] = stored
	return nil
}

func (s *RecoveryCodeStore) CountUnused(ctx context.Context, userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, c := range s.byUserID[userID] {
		if c.UsedAt == nil {
			count++
		}
	}
	return count, nil
}

func (s *RecoveryCodeStore) Consume(ctx context.Context, userID string, codeHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	codes := s.byUserID[userID]
	for i, c := range codes {
		if c.CodeHash == codeHash && c.UsedAt == nil {
			now := time.Now()
			codes[i].UsedAt = &now
			return nil
		}
	}
	return store.ErrNotFound
}

func (s *RecoveryCodeStore) DeleteAll(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byUserID, userID)
	return nil
}

var _ store.RecoveryCodeStore = (*RecoveryCodeStore)(nil)
