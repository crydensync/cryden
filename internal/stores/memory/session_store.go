package memory

import (
    "context"
    "fmt"
    "sync"
    "time"

    "github.com/crydensync/cryden/internal/core"
)

// SessionStore implements core.SessionStore with in-memory storage
type SessionStore struct {
    mu       sync.RWMutex
    byID     map[string]*core.Session
    byUser   map[string][]*core.Session
    byLookup map[string]string // lookupHash -> sessionID
}

// NewSessionStore creates a new in-memory session store
func NewSessionStore() *SessionStore {
    return &SessionStore{
        byID:     make(map[string]*core.Session),
        byUser:   make(map[string][]*core.Session),
        byLookup: make(map[string]string),
    }
}

// Create stores a new session with hashed tokens
func (s *SessionStore) Create(ctx context.Context, userID, refreshTokenHash, lookupHash string) (*core.Session, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    // Check if lookup hash already exists (should never happen with secure random)
    if _, exists := s.byLookup[lookupHash]; exists {
        return nil, fmt.Errorf("lookup hash collision - regenerate token")
    }

    session := &core.Session{
        ID:           generateID(),
        UserID:       userID,
        RefreshToken: refreshTokenHash, // bcrypt hash
        LookupHash:   lookupHash,       // SHA256 lookup hash
        CreatedAt:    time.Now(),
        ExpiresAt:    time.Now().Add(7 * 24 * time.Hour), // 7 days
    }

    // Store in all maps
    s.byID[session.ID] = session
    s.byLookup[lookupHash] = session.ID
    s.byUser[userID] = append(s.byUser[userID], session)

    return session, nil
}

// GetByRefreshToken finds session using lookup hash
func (s *SessionStore) GetByRefreshToken(ctx context.Context, lookupHash string) (*core.Session, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    // Fast lookup by index
    sessionID, exists := s.byLookup[lookupHash]
    if !exists {
        return nil, core.ErrSessionNotFound
    }

    session, exists := s.byID[sessionID]
    if !exists {
        // Inconsistent state - clean up
        delete(s.byLookup, lookupHash)
        return nil, core.ErrSessionNotFound
    }

    // Check expiration
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

    // Remove from lookup map
    delete(s.byLookup, session.LookupHash)

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
        return nil
    }

    // Remove each session
    for _, session := range sessions {
        delete(s.byLookup, session.LookupHash)
        delete(s.byID, session.ID)
    }

    // Clear user's session list
    delete(s.byUser, userID)

    return nil
}

// ListForUser returns all active sessions for a user
func (s *SessionStore) ListForUser(ctx context.Context, userID string) ([]core.Session, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    sessions, exists := s.byUser[userID]
    if !exists {
        return []core.Session{}, nil
    }

    now := time.Now()
    var active []core.Session
    for _, session := range sessions {
        if now.Before(session.ExpiresAt) {
            // Return a copy to prevent modification
            active = append(active, *session)
        }
    }

    return active, nil
}

/*
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
        // Don't expose lookup hash in list responses
        result[i].LookupHash = ""
    }

    return result, nil
}
*/

// Helper function to generate IDs
func generateID() string {
    return fmt.Sprintf("sess_%d", time.Now().UnixNano())
}

func (s *SessionStore) Close() error {
    // Memory store doesn't need cleanup
    return nil
}
