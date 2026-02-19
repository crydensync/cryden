package memory

import (
	"context"
	"sync"
	"time"
	
	"github.com/raymondproguy/credensync/core"
)

// SessionStore implements core.SessionStore in memory
type SessionStore struct {
	mu       sync.RWMutex
	byToken  map[string]*core.Session
	byUser   map[string][]*core.Session
	byID     map[string]*core.Session
}

// NewSessionStore creates a new in-memory session store
func NewSessionStore() *SessionStore {
	return &SessionStore{
		byToken: make(map[string]*core.Session),
		byUser:  make(map[string][]*core.Session),
		byID:    make(map[string]*core.Session),
	}
}

// Create stores a new session
func (s *SessionStore) Create(ctx context.Context, userID string) (*core.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Create session
	session := &core.Session{
		ID:           generateID(),
		UserID:       userID,
		RefreshToken: generateID(), // Simple for now
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour * 7), // 7 days
	}
	
	// Store by token
	s.byToken[session.RefreshToken] = session
	
	// Store by ID
	s.byID[session.ID] = session
	
	// Store in user's session list
	s.byUser[userID] = append(s.byUser[userID], session)
	
	return session, nil
}

// GetByRefreshToken retrieves a session by its refresh token
func (s *SessionStore) GetByRefreshToken(ctx context.Context, refreshToken string) (*core.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	session, exists := s.byToken[refreshToken]
	if !exists {
		return nil, core.ErrSessionNotFound
	}
	
	// Check if expired
	if time.Now().After(session.ExpiresAt) {
		return nil, core.ErrInvalidToken
	}
	
	return session, nil
}

// Revoke removes a specific session
func (s *SessionStore) Revoke(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	session, exists := s.byID[sessionID]
	if !exists {
		return core.ErrSessionNotFound
	}
	
	// Remove from token map
	delete(s.byToken, session.RefreshToken)
	
	// Remove from ID map
	delete(s.byID, sessionID)
	
	// Remove from user's session list
	userSessions := s.byUser[session.UserID]
	for i, sess := range userSessions {
		if sess.ID == sessionID {
			// Remove by swapping with last element
			userSessions[i] = userSessions[len(userSessions)-1]
			s.byUser[session.UserID] = userSessions[:len(userSessions)-1]
			break
		}
	}
	
	return nil
}

// RevokeAllForUser removes all sessions for a user
func (s *SessionStore) RevokeAllForUser(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	sessions, exists := s.byUser[userID]
	if !exists {
		return nil // No sessions to revoke
	}
	
	// Remove each session
	for _, session := range sessions {
		delete(s.byToken, session.RefreshToken)
		delete(s.byID, session.ID)
	}
	
	// Clear user's session list
	delete(s.byUser, userID)
	
	return nil
}

// ListForUser returns all sessions for a user
func (s *SessionStore) ListForUser(ctx context.Context, userID string) ([]core.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	sessions, exists := s.byUser[userID]
	if !exists {
		return []core.Session{}, nil
	}
	
	// Return a copy to prevent modification
	result := make([]core.Session, len(sessions))
	for i, session := range sessions {
		result[i] = *session
	}
	
	return result, nil
}
