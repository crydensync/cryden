package auth

import (
	"context"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
)

// SignUp creates a new user. callerIP is required and used only as a
// rate-limit key and audit metadata — the engine never infers it.
//
// policy and breachChecker are both optional (nil-safe). If policy is
// the zero value, security.DefaultPasswordPolicy is used instead —
// password strength isn't an opt-in feature the way TOTP/WebAuthn
// are, so there's no "unconfigured means off" state for it. Policy is
// checked before the breach check, cheapest/local first. A
// breachChecker error (the check service itself failing) fails open —
// it's logged, not treated as a rejection; only a confirmed breach
// blocks the password.
func SignUp(
	ctx context.Context,
	users store.UserStore,
	hasher security.Hasher,
	ids security.IDGenerator,
	limiter security.RateLimiter,
	breachChecker security.BreachedPasswordChecker,
	audit store.AuditStore,
	log logger.Logger,
	policy security.PasswordPolicy,
	email string,
	password string,
	callerIP string,
) (store.User, error) {
	allowed, err := limiter.Allow(ctx, "signup:"+callerIP)
	if err != nil {
		log.Error("signup: rate limiter error", map[string]string{"error": err.Error()})
		return store.User{}, err
	}
	if !allowed {
		log.Warn("signup: rate limited", map[string]string{"ip": callerIP})
		return store.User{}, ErrRateLimited
	}

	if _, err := users.GetByEmail(ctx, email); err == nil {
		// A user with this email already exists.
		log.Warn("signup: duplicate email attempt", map[string]string{"ip": callerIP})
		return store.User{}, ErrUserExists
	}

	if violations := policy.Validate(password); len(violations) > 0 {
		return store.User{}, &ErrPasswordPolicyViolation{Violations: violations}
	}

	if breachChecker != nil {
		breached, err := breachChecker.IsBreached(ctx, password)
		if err != nil {
			log.Error("signup: breach checker error, failing open", map[string]string{"error": err.Error()})
		} else if breached {
			if auditErr := audit.Record(ctx, store.AuditEvent{
				Type: store.EventPasswordBreachRejected,
				IP:   callerIP,
			}); auditErr != nil {
				log.Error("signup: audit record failed", map[string]string{"error": auditErr.Error()})
			}
			return store.User{}, ErrPasswordBreached
		}
	}

	hash, err := hasher.Hash(password)
	if err != nil {
		return store.User{}, err
	}

	id, err := ids.New()
	if err != nil {
		return store.User{}, err
	}

	user := store.User{
		ID:           id,
		Email:        email,
		PasswordHash: hash,
	}

	if err := users.Create(ctx, user); err != nil {
		return store.User{}, err
	}

	if err := audit.Record(ctx, store.AuditEvent{
		Type:   store.EventSignupSuccess,
		UserID: user.ID,
		IP:     callerIP,
	}); err != nil {
		// Audit write failure should not silently pass unnoticed, but
		// it also should not fail the signup itself — the user account
		// was created successfully. Log loudly instead.
		log.Error("signup: audit record failed", map[string]string{"error": err.Error(), "user_id": user.ID})
	}

	log.Info("signup: completed", map[string]string{"user_id": user.ID})

	return user, nil
}
