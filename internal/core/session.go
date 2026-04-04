package core

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "time"

)

// ListSessions returns all active sessions for a user
func (e *Engine) ListSessions(ctx context.Context, userID string) ([]Session, error) {
    return e.sessions.ListForUser(ctx, userID)
}

// RevokeSession manually revokes a specific session
func (e *Engine) RevokeSession(ctx context.Context, sessionID string) error {
    return e.sessions.Revoke(ctx, sessionID)
}

// Logout revokes the current session
func (e *Engine) Logout(ctx context.Context, refreshToken string) error {
    // Generate lookup hash from plain token
    sha := sha256.Sum256([]byte(refreshToken))
    lookupHash := hex.EncodeToString(sha[:])
    
    session, err := e.sessions.GetByRefreshToken(ctx, lookupHash)
    if err != nil {
        return ErrInvalidToken
    }

    if err := e.sessions.Revoke(ctx, session.ID); err != nil {
        return err
    }

    e.auditLogger.Log(ctx, AuditEntry{
        Timestamp: time.Now(),
        UserID:    session.UserID,
        Action:    ActionSignOut,
        Status:    "SUCCESS",
        IPAddress: getClientIP(ctx),
    })

    return nil
}

// LogoutAll revokes ALL sessions for a user
func (e *Engine) LogoutAll(ctx context.Context, userID string) error {
    if err := e.sessions.RevokeAllForUser(ctx, userID); err != nil {
        return err
    }

    e.auditLogger.Log(ctx, AuditEntry{
        Timestamp: time.Now(),
        UserID:    userID,
        Action:    ActionSignOutAll,
        Status:    "SUCCESS",
        IPAddress: getClientIP(ctx),
    })

    return nil
}
