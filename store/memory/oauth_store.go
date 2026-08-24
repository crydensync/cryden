package memory

import (
	"context"
	"sync"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// OAuthStore is an in-memory store.OAuthStore implementation for
// tests and local experimentation only — not a supported v1
// production backend. The Postgres implementation is authoritative
// for prod.
type OAuthStore struct {
	mu   sync.Mutex
	byID map[string]store.OAuthIdentity
}

func NewOAuthStore() *OAuthStore {
	return &OAuthStore{byID: make(map[string]store.OAuthIdentity)}
}

func (s *OAuthStore) Link(ctx context.Context, identity store.OAuthIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity.CreatedAt = time.Now()
	s.byID[identity.ID] = identity
	return nil
}

func (s *OAuthStore) GetByProviderID(ctx context.Context, provider, externalID string) (store.OAuthIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.byID {
		if id.Provider == provider && id.ExternalID == externalID {
			return id, nil
		}
	}
	return store.OAuthIdentity{}, store.ErrNotFound
}

func (s *OAuthStore) ListByUser(ctx context.Context, userID string) ([]store.OAuthIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []store.OAuthIdentity{}
	for _, id := range s.byID {
		if id.UserID == userID {
			out = append(out, id)
		}
	}
	return out, nil
}

func (s *OAuthStore) Unlink(ctx context.Context, identityID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[identityID]; !ok {
		return store.ErrNotFound
	}
	delete(s.byID, identityID)
	return nil
}

var _ store.OAuthStore = (*OAuthStore)(nil)
