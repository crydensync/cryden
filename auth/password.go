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
// newPassword is checked against policy and, if breachChecker is set,
// against known breaches — same enforcement and same fail-open-on-
// checker-error behavior as SignUp; see its doc comment. Checked
// AFTER the current-password verification, so a caller can't use this
// to probe policy/breach status without already proving they own the
// account.
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
	breachChecker security.BreachedPasswordChecker,
	audit store.AuditStore,
	log logger.Logger,
	policy security.PasswordPolicy,
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

	if violations := policy.Validate(newPassword); len(violations) > 0 {
		return &ErrPasswordPolicyViolation{Violations: violations}
	}

	if breachChecker != nil {
		breached, err := breachChecker.IsBreached(ctx, newPassword)
		if err != nil {
			log.Error("change password: breach checker error, failing open", map[string]string{"error": err.Error(), "user_id": userID})
		} else if breached {
			if auditErr := audit.Record(ctx, store.AuditEvent{
				Type:   store.EventPasswordBreachRejected,
				UserID: userID,
			}); auditErr != nil {
				log.Error("change password: audit record failed", map[string]string{"error": auditErr.Error(), "user_id": userID})
			}
			return ErrPasswordBreached
		}
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
