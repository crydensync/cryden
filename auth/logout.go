package auth

import (
	"context"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/store"
)

// Logout revokes a single session (one device). Verifies the session
// actually belongs to userID before revoking — without this check,
// anyone who merely knows a sessionID could revoke another user's
// session.
func Logout(
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
		log.Warn("logout: ownership mismatch attempt", map[string]string{
			"session_id":      sessionID,
			"requesting_user": userID,
		})
		return store.ErrSessionNotOwned
	}

	if err := sessions.Revoke(ctx, sessionID); err != nil {
		return err
	}

	if err := audit.Record(ctx, store.AuditEvent{
		Type:   store.EventLogout,
		UserID: userID,
	}); err != nil {
		log.Error("logout: audit record failed", map[string]string{"error": err.Error(), "user_id": userID})
	}

	log.Info("logout: completed", map[string]string{"user_id": userID, "session_id": sessionID})
	return nil
}

// LogoutAll revokes every session belonging to userID (all devices).
func LogoutAll(
	ctx context.Context,
	sessions store.SessionStore,
	audit store.AuditStore,
	log logger.Logger,
	userID string,
) error {
	if err := sessions.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}

	if err := audit.Record(ctx, store.AuditEvent{
		Type:   store.EventLogoutAll,
		UserID: userID,
	}); err != nil {
		log.Error("logout_all: audit record failed", map[string]string{"error": err.Error(), "user_id": userID})
	}

	log.Info("logout_all: completed", map[string]string{"user_id": userID})
	return nil
}
