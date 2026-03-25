package sqlite

import (
    "context"
    "database/sql"
    "fmt"
    "time"

    "github.com/crydensync/cryden/internal/core"
    _ "github.com/mattn/go-sqlite3"
)

// SessionStore implements core.SessionStore with SQLite
type SessionStore struct {
    db *sql.DB
}

// NewSessionStore creates a new SQLite session store
func NewSessionStore(db *sql.DB) *SessionStore {
    return &SessionStore{db: db}
}

// Create stores a new session with hashed tokens
func (s *SessionStore) Create(ctx context.Context, userID, refreshTokenHash, lookupHash string) (*core.Session, error) {
    query := `
    INSERT INTO sessions (id, user_id, refresh_token, lookup_hash, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
    RETURNING id, user_id, refresh_token, lookup_hash, created_at, expires_at
    `

    id := fmt.Sprintf("sess_%d", time.Now().UnixNano())
    now := time.Now()
    expiresAt := now.Add(7 * 24 * time.Hour)

    var session core.Session
    err := s.db.QueryRowContext(ctx, query,
        id, userID, refreshTokenHash, lookupHash, now, expiresAt,
    ).Scan(
        &session.ID,
        &session.UserID,
        &session.RefreshToken,
        &session.LookupHash,
        &session.CreatedAt,
        &session.ExpiresAt,
    )

    if err != nil {
        return nil, fmt.Errorf("failed to create session: %w", err)
    }

    return &session, nil
}

// GetByRefreshToken finds session using lookup hash
func (s *SessionStore) GetByRefreshToken(ctx context.Context, lookupHash string) (*core.Session, error) {
    query := `
    SELECT id, user_id, refresh_token, lookup_hash, created_at, expires_at
    FROM sessions
    WHERE lookup_hash = ? AND expires_at > ?
    `

    var session core.Session
    err := s.db.QueryRowContext(ctx, query, lookupHash, time.Now()).Scan(
        &session.ID,
        &session.UserID,
        &session.RefreshToken,
        &session.LookupHash,
        &session.CreatedAt,
        &session.ExpiresAt,
    )

    if err == sql.ErrNoRows {
        return nil, core.ErrSessionNotFound
    }
    if err != nil {
        return nil, fmt.Errorf("failed to get session: %w", err)
    }

    return &session, nil
}

// Revoke removes a specific session
func (s *SessionStore) Revoke(ctx context.Context, sessionID string) error {
    query := `DELETE FROM sessions WHERE id = ?`

    result, err := s.db.ExecContext(ctx, query, sessionID)
    if err != nil {
        return fmt.Errorf("failed to revoke session: %w", err)
    }

    rows, _ := result.RowsAffected()
    if rows == 0 {
        return core.ErrSessionNotFound
    }

    return nil
}

// RevokeAllForUser removes all sessions for a user
func (s *SessionStore) RevokeAllForUser(ctx context.Context, userID string) error {
    query := `DELETE FROM sessions WHERE user_id = ?`

    _, err := s.db.ExecContext(ctx, query, userID)
    if err != nil {
        return fmt.Errorf("failed to revoke all sessions: %w", err)
    }

    return nil
}

// ListForUser returns all active sessions for a user
func (s *SessionStore) ListForUser(ctx context.Context, userID string) ([]core.Session, error) {
    query := `
    SELECT id, user_id, refresh_token, created_at, expires_at
    FROM sessions
    WHERE user_id = ? AND expires_at > ?
    ORDER BY created_at DESC
    `

    rows, err := s.db.QueryContext(ctx, query, userID, time.Now())
    if err != nil {
        return nil, fmt.Errorf("failed to list sessions: %w", err)
    }
    defer rows.Close()

    var sessions []core.Session
    for rows.Next() {
        var session core.Session
        err := rows.Scan(
            &session.ID,
            &session.UserID,
            &session.RefreshToken,
            &session.CreatedAt,
            &session.ExpiresAt,
        )
        if err != nil {
            return nil, fmt.Errorf("failed to scan session: %w", err)
        }
        session.LookupHash = ""
        sessions = append(sessions, session)
    }

    return sessions, nil
}

func (s *SessionStore) Close() error {
    if s.db != nil {
        return s.db.Close()
    }
    return nil
}
