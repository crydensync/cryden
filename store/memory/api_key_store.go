package memory

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// APIKeyStore is an in-memory store.APIKeyStore implementation for
// tests and local experimentation only — not a supported production
// backend. The Postgres and SQLite implementations are authoritative.
type APIKeyStore struct {
	mu sync.Mutex
	// byHash is the primary index, because the hash is what
	// authentication looks a key up by. Keyed by hash rather than by ID
	// so that path stays a map hit here too, matching the unique index
	// it is in the SQL backends.
	byHash map[string]store.APIKey
}

func NewAPIKeyStore() *APIKeyStore {
	return &APIKeyStore{byHash: make(map[string]store.APIKey)}
}

func (s *APIKeyStore) Create(ctx context.Context, key store.APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key.CreatedAt.IsZero() {
		key.CreatedAt = time.Now()
	}
	key.Scopes = slices.Clone(key.Scopes)
	s.byHash[key.KeyHash] = key
	return nil
}

func (s *APIKeyStore) GetByKeyHash(ctx context.Context, keyHash string) (store.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.byHash[keyHash]
	if !ok {
		return store.APIKey{}, store.ErrNotFound
	}
	key.Scopes = slices.Clone(key.Scopes)
	return key, nil
}

func (s *APIKeyStore) ListByUser(ctx context.Context, userID string) ([]store.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.APIKey
	for _, key := range s.byHash {
		if key.UserID != userID || key.RevokedAt != nil {
			continue
		}
		key.Scopes = slices.Clone(key.Scopes)
		out = append(out, key)
	}
	// Map iteration order is random, and the interface promises
	// newest-first. Ties break on ID so a batch created inside one clock
	// tick still comes back in a stable order.
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *APIKeyStore) Revoke(ctx context.Context, userID, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, key := range s.byHash {
		if key.ID != keyID || key.UserID != userID || key.RevokedAt != nil {
			continue
		}
		now := time.Now()
		key.RevokedAt = &now
		s.byHash[hash] = key
		return nil
	}
	return store.ErrNotFound
}

func (s *APIKeyStore) TouchLastUsed(ctx context.Context, keyID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, key := range s.byHash {
		if key.ID != keyID {
			continue
		}
		key.LastUsedAt = &at
		s.byHash[hash] = key
		return nil
	}
	// Not an error: the interface documents a zero-row update as
	// acceptable, and the caller is fire-and-forget.
	return nil
}

var _ store.APIKeyStore = (*APIKeyStore)(nil)
