package memory

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// WebAuthnStore is an in-memory store.WebAuthnCredentialStore
// implementation for tests and local experimentation only — not a
// supported production backend. The Postgres implementation is
// authoritative for prod.
type WebAuthnStore struct {
	mu    sync.Mutex
	byRow map[string]store.WebAuthnCredential // keyed by our own row ID
}

func NewWebAuthnStore() *WebAuthnStore {
	return &WebAuthnStore{byRow: make(map[string]store.WebAuthnCredential)}
}

func (s *WebAuthnStore) Add(ctx context.Context, cred store.WebAuthnCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cred.CreatedAt = time.Now()
	s.byRow[cred.ID] = cred
	return nil
}

func (s *WebAuthnStore) ListByUser(ctx context.Context, userID string) ([]store.WebAuthnCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.WebAuthnCredential
	for _, c := range s.byRow {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *WebAuthnStore) Update(ctx context.Context, cred store.WebAuthnCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, existing := range s.byRow {
		if bytes.Equal(existing.CredentialID, cred.CredentialID) {
			existing.CredentialData = cred.CredentialData
			existing.LastUsedAt = cred.LastUsedAt
			s.byRow[id] = existing
			return nil
		}
	}
	return store.ErrNotFound
}

func (s *WebAuthnStore) Delete(ctx context.Context, userID string, credentialID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, existing := range s.byRow {
		if existing.UserID == userID && bytes.Equal(existing.CredentialID, credentialID) {
			delete(s.byRow, id)
			return nil
		}
	}
	return store.ErrNotFound
}

var _ store.WebAuthnCredentialStore = (*WebAuthnStore)(nil)
