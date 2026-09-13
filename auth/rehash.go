package auth

import (
	"context"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
)

// upgradePasswordHash rewrites a verified password's stored hash when
// the hasher reports it out of date — a different algorithm, or the same
// one at costs since raised. This is what actually migrates a user base:
// changing Config.Hasher only changes what NEW hashes look like, and
// without this every account that never changes its password would stay
// on the old algorithm forever.
//
// Called only after Compare has already succeeded, so the plaintext is
// known correct, and only from the password login path — magic-link,
// OAuth and second-factor logins never see a plaintext password to
// rehash from.
//
// Returns nothing, deliberately. The login has already succeeded by this
// point; a failed rewrite means the old hash stays and is tried again on
// the next login, which is strictly better than turning a background
// improvement into a failed sign-in. Every failure is logged instead.
func upgradePasswordHash(
	ctx context.Context,
	users store.UserStore,
	hasher security.Hasher,
	audit store.AuditStore,
	log logger.Logger,
	user store.User,
	password string,
	callerIP string,
) {
	// A host-supplied Hasher that implements only Hash and Compare opts
	// out of this by construction — the engine has no way to know what
	// "out of date" would mean for it.
	rehasher, ok := hasher.(security.Rehasher)
	if !ok || !rehasher.NeedsRehash(user.PasswordHash) {
		return
	}

	newHash, err := hasher.Hash(password)
	if err != nil {
		log.Error("login: password rehash failed", map[string]string{"error": err.Error(), "user_id": user.ID})
		return
	}
	if err := users.UpdatePasswordHash(ctx, user.ID, newHash); err != nil {
		log.Error("login: password rehash store error", map[string]string{"error": err.Error(), "user_id": user.ID})
		return
	}

	from := string(security.IdentifyHash(user.PasswordHash))
	to := string(security.IdentifyHash(newHash))
	if err := audit.Record(ctx, store.AuditEvent{
		Type:     store.EventPasswordHashUpgraded,
		UserID:   user.ID,
		IP:       callerIP,
		Metadata: map[string]string{"from": from, "to": to},
	}); err != nil {
		log.Error("login: audit record failed", map[string]string{"error": err.Error()})
	}
	log.Info("login: password hash upgraded", map[string]string{"user_id": user.ID, "from": from, "to": to})
}
