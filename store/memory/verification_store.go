package memory

import (
	"context"
	"sync"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// VerificationStore is an in-memory store.VerificationStore
// implementation for tests and local experimentation only.
type VerificationStore struct {
	mu   sync.Mutex
	byID map[string]store.VerificationToken
}

func NewVerificationStore() *VerificationStore {
	return &VerificationStore{byID: make(map[string]store.VerificationToken)}
}

func (s *VerificationStore) Create(ctx context.Context, vt store.VerificationToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	vt.CreatedAt = time.Now()
	s.byID[vt.ID] = vt
	return nil
}

func (s *VerificationStore) GetByTokenHash(ctx context.Context, tokenHash string) (store.VerificationToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, vt := range s.byID {
		if vt.TokenHash == tokenHash {
			return vt, nil
		}
	}
	return store.VerificationToken{}, store.ErrNotFound
}

func (s *VerificationStore) MarkUsed(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	vt, ok := s.byID[id]
	if !ok {
		return store.ErrNotFound
	}
	now := time.Now()
	vt.UsedAt = &now
	s.byID[id] = vt
	return nil
}

var _ store.VerificationStore = (*VerificationStore)(nil)
