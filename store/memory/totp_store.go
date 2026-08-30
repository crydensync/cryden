package memory

import (
	"context"
	"sync"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// TOTPStore is an in-memory store.TOTPStore implementation for tests
// and local experimentation only — not a supported production
// backend. The Postgres implementation is authoritative for prod.
type TOTPStore struct {
	mu   sync.Mutex
	byID map[string]store.TOTPSecret
}

func NewTOTPStore() *TOTPStore {
	return &TOTPStore{byID: make(map[string]store.TOTPSecret)}
}

func (s *TOTPStore) Upsert(ctx context.Context, secret store.TOTPSecret) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret.CreatedAt = time.Now()
	secret.ConfirmedAt = nil
	s.byID[secret.UserID] = secret
	return nil
}

func (s *TOTPStore) GetByUserID(ctx context.Context, userID string) (store.TOTPSecret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, ok := s.byID[userID]
	if !ok {
		return store.TOTPSecret{}, store.ErrNotFound
	}
	return secret, nil
}

func (s *TOTPStore) Confirm(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, ok := s.byID[userID]
	if !ok {
		return store.ErrNotFound
	}
	now := time.Now()
	secret.ConfirmedAt = &now
	s.byID[userID] = secret
	return nil
}

func (s *TOTPStore) Delete(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[userID]; !ok {
		return store.ErrNotFound
	}
	delete(s.byID, userID)
	return nil
}

var _ store.TOTPStore = (*TOTPStore)(nil)
