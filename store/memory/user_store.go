package memory

import (
	"context"
	"sync"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// UserStore is an in-memory store.UserStore implementation for tests
// and local experimentation only — not a supported v1 production
// backend. The Postgres implementation is authoritative for prod.
type UserStore struct {
	mu    sync.Mutex
	byID  map[string]store.User
}

func NewUserStore() *UserStore {
	return &UserStore{byID: make(map[string]store.User)}
}

func (s *UserStore) Create(ctx context.Context, user store.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now
	s.byID[user.ID] = user
	return nil
}

func (s *UserStore) GetByEmail(ctx context.Context, email string) (store.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.byID {
		if u.Email == email {
			return u, nil
		}
	}
	return store.User{}, store.ErrNotFound
}

func (s *UserStore) GetByID(ctx context.Context, id string) (store.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	if !ok {
		return store.User{}, store.ErrNotFound
	}
	return u, nil
}

func (s *UserStore) UpdateEmail(ctx context.Context, id string, newEmail string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	if !ok {
		return store.ErrNotFound
	}
	u.Email = newEmail
	u.UpdatedAt = time.Now()
	s.byID[id] = u
	return nil
}

func (s *UserStore) UpdatePasswordHash(ctx context.Context, id string, newHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	if !ok {
		return store.ErrNotFound
	}
	u.PasswordHash = newHash
	u.UpdatedAt = time.Now()
	s.byID[id] = u
	return nil
}

func (s *UserStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.byID, id)
	return nil
}

func (s *UserStore) IncrementFailedAttempts(ctx context.Context, id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	if !ok {
		return 0, store.ErrNotFound
	}
	u.FailedAttempts++
	s.byID[id] = u
	return u.FailedAttempts, nil
}

func (s *UserStore) ResetFailedAttempts(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	if !ok {
		return store.ErrNotFound
	}
	u.FailedAttempts = 0
	u.LockedUntil = nil
	s.byID[id] = u
	return nil
}

func (s *UserStore) LockAccount(ctx context.Context, id string, until time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	if !ok {
		return store.ErrNotFound
	}
	u.LockedUntil = &until
	s.byID[id] = u
	return nil
}

var _ store.UserStore = (*UserStore)(nil)