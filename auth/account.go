package auth

import (
	"context"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
)

// DeleteAccount permanently deletes a user. Requires the current
// password as re-confirmation — same reasoning as ChangePassword: a
// stolen access token alone should never be sufficient to trigger an
// irreversible, destructive action.
func DeleteAccount(
	ctx context.Context,
	users store.UserStore,
	sessions store.SessionStore,
	hasher security.Hasher,
	audit store.AuditStore,
	log logger.Logger,
	userID string,
	currentPassword string,
) error {
	user, err := users.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := hasher.Compare(user.PasswordHash, currentPassword); err != nil {
		log.Warn("delete account: password mismatch", map[string]string{"user_id": userID})
		return ErrInvalidCredentials
	}

	if err := sessions.RevokeAllForUser(ctx, userID); err != nil {
		log.Error("delete account: session revocation failed", map[string]string{"error": err.Error(), "user_id": userID})
	}

	// Audit BEFORE delete — the users FK is ON DELETE SET NULL, so the
	// event would lose its user_id attribution if recorded after.
	if err := audit.Record(ctx, store.AuditEvent{
		Type:   store.EventAccountDeleted,
		UserID: userID,
	}); err != nil {
		log.Error("delete account: audit record failed", map[string]string{"error": err.Error(), "user_id": userID})
	}

	if err := users.Delete(ctx, userID); err != nil {
		return err
	}

	log.Info("account deleted", map[string]string{"user_id": userID})
	return nil
}
