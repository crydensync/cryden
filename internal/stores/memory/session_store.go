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
    byLookup map[string]string
}

// NewSessionStore creates a new in-memory session store
func NewSessionStore() *SessionStore {
    return &SessionStore{
        byID:     make(map[string]*core.Session),
        byUser:   make(map[string][]*core.Session),
        byLookup: make(map[string]string),
    }
}

// Create stores a new session
func (s *SessionStore) Create(ctx context.Context, userID, refreshTokenHash, lookupHash string, device *core.DeviceInfo, ipAddress string) (*core.Session, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    if _, exists := s.byLookup[lookupHash]; exists {
        return nil, fmt.Errorf("lookup hash collision")
    }

    now := time.Now()
    session := &core.Session{
        ID:           generateID(),
        UserID:       userID,
        RefreshToken: refreshTokenHash,
        LookupHash:   lookupHash,
        CreatedAt:    now,
        ExpiresAt:    now.Add(7 * 24 * time.Hour),
        LastSeenAt:   now,
        IPAddress:    ipAddress,
    }

    if device != nil {
        session.DeviceName = device.DeviceName
        session.DeviceType = device.DeviceType
        session.Browser = device.Browser
        session.OS = device.OS
    }

    s.byID[session.ID] = session
    s.byLookup[lookupHash] = session.ID
    s.byUser[userID] = append(s.byUser[userID], session)

    return session, nil
}

// UpdateLastSeen updates the last seen time for a session
func (s *SessionStore) UpdateLastSeen(ctx context.Context, sessionID string) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    session, exists := s.byID[sessionID]
    if !exists {
        return core.ErrSessionNotFound
    }

    session.LastSeenAt = time.Now()
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

    now := time.Now()
    var active []core.Session
    for _, session := range sessions {
        if now.Before(session.ExpiresAt) {
            activeSession := *session
            activeSession.LookupHash = ""
            active = append(active, activeSession)
        }
    }

    return active, nil
}

// GetByRefreshToken finds session using lookup hash
func (s *SessionStore) GetByRefreshToken(ctx context.Context, lookupHash string) (*core.Session, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    sessionID, exists := s.byLookup[lookupHash]
    if !exists {
        return nil, core.ErrSessionNotFound
    }

    session, exists := s.byID[sessionID]
    if !exists {
        delete(s.byLookup, lookupHash)
        return nil, core.ErrSessionNotFound
    }

    // Return a copy to prevent modification
    sessionCopy := *session
    return &sessionCopy, nil
}

// Revoke removes a specific session
func (s *SessionStore) Revoke(ctx context.Context, sessionID string) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    session, exists := s.byID[sessionID]
    if !exists {
        return core.ErrSessionNotFound
    }

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

    delete(s.byUser, userID)

    return nil
}

// Helper function to generate IDs
func generateID() string {
    return fmt.Sprintf("sess_%d", time.Now().UnixNano())
}

func (s *SessionStore) Close() error {
    // Memory store doesn't need cleanup
    return nil
}
