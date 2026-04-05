package postgres

import (
    "context"
    "database/sql"
    "fmt"
    "time"

    "github.com/crydensync/cryden/internal/core"
    _ "github.com/lib/pq"
)

type SessionStore struct {
    db *sql.DB
}

func NewSessionStore(db *sql.DB) *SessionStore {
    return &SessionStore{db: db}
}

// Create stores a new session with device info
func (s *SessionStore) Create(ctx context.Context, userID, refreshTokenHash, lookupHash string, device *core.DeviceInfo, ipAddress string) (*core.Session, error) {
    query := `
    INSERT INTO sessions (id, user_id, refresh_token, lookup_hash, created_at, expires_at, last_seen_at, ip_address, device_name, device_type, browser, os)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    RETURNING id, user_id, refresh_token, lookup_hash, created_at, expires_at, last_seen_at, ip_address, device_name, device_type, browser, os
    `

    id := fmt.Sprintf("sess_%d", time.Now().UnixNano())
    now := time.Now()
    expiresAt := now.Add(7 * 24 * time.Hour)
    
    deviceName := ""
    deviceType := ""
    browser := ""
    os := ""
    
    if device != nil {
        deviceName = device.DeviceName
        deviceType = device.DeviceType
        browser = device.Browser
        os = device.OS
    }

    var session core.Session
    err := s.db.QueryRowContext(ctx, query,
        id, userID, refreshTokenHash, lookupHash, now, expiresAt, now, ipAddress,
        deviceName, deviceType, browser, os,
    ).Scan(
        &session.ID,
        &session.UserID,
        &session.RefreshToken,
        &session.LookupHash,
        &session.CreatedAt,
        &session.ExpiresAt,
        &session.LastSeenAt,
        &session.IPAddress,
        &session.DeviceName,
        &session.DeviceType,
        &session.Browser,
        &session.OS,
    )

    if err != nil {
        return nil, fmt.Errorf("failed to create session: %w", err)
    }

    return &session, nil
}

// GetByRefreshToken finds session using lookup hash
func (s *SessionStore) GetByRefreshToken(ctx context.Context, lookupHash string) (*core.Session, error) {
    query := `
    SELECT id, user_id, refresh_token, lookup_hash, created_at, expires_at, last_seen_at, ip_address, device_name, device_type, browser, os
    FROM sessions
    WHERE lookup_hash = $1 AND expires_at > $2
    `

    var session core.Session
    err := s.db.QueryRowContext(ctx, query, lookupHash, time.Now()).Scan(
        &session.ID,
        &session.UserID,
        &session.RefreshToken,
        &session.LookupHash,
        &session.CreatedAt,
        &session.ExpiresAt,
        &session.LastSeenAt,
        &session.IPAddress,
        &session.DeviceName,
        &session.DeviceType,
        &session.Browser,
        &session.OS,
    )

    if err == sql.ErrNoRows {
        return nil, core.ErrSessionNotFound
    }
    if err != nil {
        return nil, fmt.Errorf("failed to get session: %w", err)
    }

    return &session, nil
}

// UpdateLastSeen updates the last seen time for a session
func (s *SessionStore) UpdateLastSeen(ctx context.Context, sessionID string) error {
    query := `UPDATE sessions SET last_seen_at = $1 WHERE id = $2`

    result, err := s.db.ExecContext(ctx, query, time.Now(), sessionID)
    if err != nil {
        return fmt.Errorf("failed to update last seen: %w", err)
    }

    rows, _ := result.RowsAffected()
    if rows == 0 {
        return core.ErrSessionNotFound
    }

    return nil
}

// Revoke removes a specific session
func (s *SessionStore) Revoke(ctx context.Context, sessionID string) error {
    query := `DELETE FROM sessions WHERE id = $1`

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
    query := `DELETE FROM sessions WHERE user_id = $1`

    _, err := s.db.ExecContext(ctx, query, userID)
    if err != nil {
        return fmt.Errorf("failed to revoke all sessions: %w", err)
    }

    return nil
}

// ListForUser returns all active sessions for a user
func (s *SessionStore) ListForUser(ctx context.Context, userID string) ([]core.Session, error) {
    query := `
    SELECT id, user_id, refresh_token, created_at, expires_at, last_seen_at, ip_address, device_name, device_type, browser, os
    FROM sessions
    WHERE user_id = $1 AND expires_at > $2
    ORDER BY last_seen_at DESC
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
            &session.LastSeenAt,
            &session.IPAddress,
            &session.DeviceName,
            &session.DeviceType,
            &session.Browser,
            &session.OS,
        )
        if err != nil {
            return nil, fmt.Errorf("failed to scan session: %w", err)
        }
        session.LookupHash = ""
        sessions = append(sessions, session)
    }

    return sessions, nil
}
