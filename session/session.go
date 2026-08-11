package session

import (
	"context"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/store"
)

// List returns all active sessions for a user (for a settings page
// "your devices" view). Includes IP and UserAgent so the caller's UI
// can display recognizable device info.
func List(ctx context.Context, sessions store.SessionStore, userID string) ([]store.Session, error) {
	return sessions.ListByUser(ctx, userID)
}

// Revoke revokes a specific session. Verifies the session belongs to
// userID before revoking — same ownership check as auth.Logout, so a
// caller who only knows a sessionID (e.g. from a shared/leaked value)
// cannot revoke another user's session.
func Revoke(
	ctx context.Context,
	sessions store.SessionStore,
	audit store.AuditStore,
	log logger.Logger,
	sessionID string,
	userID string,
) error {
	session, err := sessions.GetByID(ctx, sessionID)
	if err != nil {
		return err
	}
	if session.UserID != userID {
		log.Warn("session revoke: ownership mismatch attempt", map[string]string{
			"session_id":      sessionID,
			"requesting_user": userID,
		})
		return store.ErrSessionNotOwned
	}

	if err := sessions.Revoke(ctx, sessionID); err != nil {
		return err
	}

	if err := audit.Record(ctx, store.AuditEvent{
		Type:   store.EventSessionRevoked,
		UserID: userID,
		Metadata: map[string]string{"session_id": sessionID},
	}); err != nil {
		log.Error("session revoke: audit record failed", map[string]string{"error": err.Error(), "user_id": userID})
	}

	log.Info("session revoke: completed", map[string]string{"user_id": userID, "session_id": sessionID})
	return nil
}