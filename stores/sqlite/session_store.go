package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/raymondproguy/credensync/core"
)

// SessionStore implements core.SessionStore using SQLite
type SessionStore struct {
	db *sql.DB
}

// NewSessionStore creates a new SQLite session store
func NewSessionStore(db *sql.DB) *SessionStore {
	return &SessionStore{db: db}
}

// Create stores a new session
func (s *SessionStore) Create(ctx context.Context, userID string) (*core.Session, error) {
	query :=
		`INSERT INTO sessions (id, user_id, refresh_token, created_at, expires_at)
  VALUES (?, ?, ?, ?, ?)
  RETURNING id, user_id, refresh_token, created_at, expires_at
	`

	now := time.Now()
	sessionID := generateSessionID()
	refreshToken := generateRefreshToken()
	expiresAt := now.Add(24 * time.Hour * 7)

	var session core.Session
	err := s.db.QueryRowContext(ctx, query, sessionID, userID, refreshToken, now, expiresAt).Scan(&session.ID, &session.UserID, &session.RefreshToken, &session.CreatedAt, &session.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &session, nil
}

// GetByRefreshToken retrieves a session by refresh token
func (s *SessionStore) GetByRefreshToken(ctx context.Context, refreshToken string) (*core.Session, error) {
	query := `
  SELECT id, user_id, refresh_token, created_at, expires_at
  FROM sessions
  WHERE refresh_token = ? AND expires_at > ?
`

	var session core.Session
	err := s.db.QueryRowContext(ctx, query, refreshToken, time.Now()).Scan(&session.ID, &session.UserID, &session.RefreshToken, &session.CreatedAt, &session.ExpiresAt)

	if err == sql.ErrNoRows {
		return nil, core.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w:", err)
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

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
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

// ListForUser returns all sessions for a user
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
		err := rows.Scan(&session.ID, &session.UserID, &session.RefreshToken, &session.CreatedAt, &session.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}

// Close closes the database connection
func (s *SessionStore) Close() error {
	return s.db.Close()
}

// generateSessionID creates a unique session ID
func generateSessionID() string {
	return fmt.Sprintf("sess_%d", time.Now().UnixNano())
}

// generateRefreshToken creates a unique refresh token
func generateRefreshToken() string {
	return fmt.Sprintf("ref_%d", time.Now().UnixNano())
}
