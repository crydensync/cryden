package core

import (
    "context"
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
    session, err := e.sessions.GetByRefreshToken(ctx, refreshToken)
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
