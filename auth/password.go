package auth

import (
	"context"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
)

// ChangePassword requires the caller to supply their CURRENT password
// as proof of ongoing authorization — never allow a password change
// from just a valid access token alone, since a stolen access token
// would then be enough to lock the real owner out permanently.
//
// NOTE: run your ValidatePassword policy check on newPassword BEFORE
// calling this — same as SignUp, fail on bad input before touching
// the DB or spending bcrypt's CPU cost.
//
// On success, ALL sessions are revoked (including the one making this
// request) — if the old password leaked, any session an attacker
// already opened must die too. The caller re-logs in with the new
// password afterward.
func ChangePassword(
	ctx context.Context,
	users store.UserStore,
	sessions store.SessionStore,
	hasher security.Hasher,
	audit store.AuditStore,
	log logger.Logger,
	userID string,
	currentPassword string,
	newPassword string,
) error {
	user, err := users.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := hasher.Compare(user.PasswordHash, currentPassword); err != nil {
		log.Warn("change password: current password mismatch", map[string]string{"user_id": userID})
		return ErrInvalidCredentials
	}

	newHash, err := hasher.Hash(newPassword)
	if err != nil {
		return err
	}

	if err := users.UpdatePasswordHash(ctx, userID, newHash); err != nil {
		return err
	}

	if err := sessions.RevokeAllForUser(ctx, userID); err != nil {
		// Password WAS changed successfully at this point — don't
		// reverse that. Log loudly; a stuck old session is a smaller
		// risk than silently failing an already-applied password change.
		log.Error("change password: session revocation failed", map[string]string{"error": err.Error(), "user_id": userID})
	}

	if err := audit.Record(ctx, store.AuditEvent{
		Type:   store.EventPasswordChanged,
		UserID: userID,
	}); err != nil {
		log.Error("change password: audit record failed", map[string]string{"error": err.Error(), "user_id": userID})
	}

	log.Info("change password: completed", map[string]string{"user_id": userID})
	return nil
}
