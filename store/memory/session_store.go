package memory

import (
	"context"
	"sync"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// SessionStore is an in-memory store.SessionStore implementation for
// tests and local experimentation only.
type SessionStore struct {
	mu   sync.Mutex
	byID map[string]store.Session
}

func NewSessionStore() *SessionStore {
	return &SessionStore{byID: make(map[string]store.Session)}
}

func (s *SessionStore) Create(ctx context.Context, sess store.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess.CreatedAt = time.Now()
	s.byID[sess.ID] = sess
	return nil
}

func (s *SessionStore) GetByID(ctx context.Context, sessionID string) (store.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[sessionID]
	if !ok {
		return store.Session{}, store.ErrNotFound
	}
	return sess, nil
}

func (s *SessionStore) GetByTokenHash(ctx context.Context, tokenHash string) (store.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.byID {
		if sess.TokenHash == tokenHash {
			return sess, nil
		}
	}
	return store.Session{}, store.ErrNotFound
}

func (s *SessionStore) ListByUser(ctx context.Context, userID string) ([]store.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.Session
	for _, sess := range s.byID {
		if sess.UserID == userID && sess.RevokedAt == nil {
			out = append(out, sess)
		}
	}
	return out, nil
}

func (s *SessionStore) Revoke(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[sessionID]
	if !ok {
		return store.ErrNotFound
	}
	now := time.Now()
	sess.RevokedAt = &now
	s.byID[sessionID] = sess
	return nil
}

func (s *SessionStore) RevokeFamily(ctx context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, sess := range s.byID {
		if sess.FamilyID == familyID && sess.RevokedAt == nil {
			sess.RevokedAt = &now
			s.byID[id] = sess
		}
	}
	return nil
}

func (s *SessionStore) RevokeAllForUser(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, sess := range s.byID {
		if sess.UserID == userID && sess.RevokedAt == nil {
			sess.RevokedAt = &now
			s.byID[id] = sess
		}
	}
	return nil
}

// RotateToken atomically revokes oldSessionID and creates newSession.
// The in-memory implementation holds the mutex across both operations
// to simulate the transactional guarantee the Postgres implementation
// provides via a real DB transaction.
func (s *SessionStore) RotateToken(ctx context.Context, oldSessionID string, newSession store.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	old, ok := s.byID[oldSessionID]
	if !ok {
		return store.ErrNotFound
	}
	now := time.Now()
	old.RevokedAt = &now
	s.byID[oldSessionID] = old

	newSession.CreatedAt = now
	s.byID[newSession.ID] = newSession
	return nil
}

var _ store.SessionStore = (*SessionStore)(nil)
