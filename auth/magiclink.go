package auth

import (
	"context"
	"time"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/notify"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/token"
)

// magicLinkTTL is how long a login link stays valid — fixed, not
// configurable, same reasoning as mfaPendingTTL: a passwordless login
// link is a bearer credential for the account it's mailed to, and
// making its lifetime a tuning knob invites a deployment to widen it
// well past what "click the link you just got" actually needs. 15
// minutes is generous enough to survive someone switching to their
// email app without leaving a long-lived credential sitting in an
// inbox.
const magicLinkTTL = 15 * time.Minute

// RequestMagicLink sends a passwordless login link to email, for an
// EXISTING account only — this does not create accounts. To avoid
// leaking which emails are registered, it returns nil regardless of
// whether the account exists; the email is only actually sent when it
// does. A genuine delivery failure (the sender's own error) still
// propagates for an existing account, since that's an operational
// concern distinct from enumeration — silently swallowing real send
// failures would hide delivery problems from monitoring for no real
// security benefit.
func RequestMagicLink(
	ctx context.Context,
	users store.UserStore,
	verifications store.VerificationStore,
	sender notify.MagicLinkSender,
	tokenGen token.TokenGenerator,
	ids security.IDGenerator,
	limiter security.RateLimiter,
	audit store.AuditStore,
	log logger.Logger,
	email string,
	callerIP string,
) error {
	allowed, err := limiter.Allow(ctx, "magic-link:"+callerIP+":"+email)
	if err != nil {
		log.Error("request magic link: rate limiter error", map[string]string{"error": err.Error()})
		return err
	}
	if !allowed {
		log.Warn("request magic link: rate limited", map[string]string{"ip": callerIP})
		return ErrRateLimited
	}

	user, err := users.GetByEmail(ctx, email)
	if err != nil {
		// No such account — return nil rather than an error, same
		// enumeration-avoidance reasoning as Login's nonexistent-user
		// path. Unlike Login, there's no password hash to pay the
		// cost of here — the response never contains anything for an
		// attacker to time against beyond "did an email get sent,"
		// which they can't observe directly anyway.
		log.Info("magic link requested for unknown email", map[string]string{"ip": callerIP})
		return nil
	}

	rawToken, err := tokenGen.New()
	if err != nil {
		return err
	}
	id, err := ids.New()
	if err != nil {
		return err
	}

	vt := store.VerificationToken{
		ID:        id,
		UserID:    user.ID,
		Purpose:   store.PurposeMagicLink,
		TokenHash: token.HashToken(rawToken),
		ExpiresAt: time.Now().Add(magicLinkTTL),
	}
	if err := verifications.Create(ctx, vt); err != nil {
		return err
	}

	if err := sender.SendMagicLink(ctx, email, rawToken); err != nil {
		return err
	}

	if err := audit.Record(ctx, store.AuditEvent{
		Type:   store.EventMagicLinkRequested,
		UserID: user.ID,
		IP:     callerIP,
	}); err != nil {
		log.Error("request magic link: audit record failed", map[string]string{"error": err.Error(), "user_id": user.ID})
	}

	log.Info("magic link requested", map[string]string{"user_id": user.ID})
	return nil
}

// CompleteMagicLink logs in using the raw token from a link sent by
// RequestMagicLink. The token is single-use — MarkUsed is called as
// soon as it passes validation, before any second-factor check or
// session creation, so a link can never be replayed even if something
// later in this call fails.
//
// Clicking a valid link proves email ownership, the primary factor —
// it does not bypass a confirmed second factor. This routes through
// the exact same completePrimaryAuth gate password login uses, so an
// account with TOTP/a passkey enrolled pauses here exactly as it
// would after a correct password.
func CompleteMagicLink(
	ctx context.Context,
	users store.UserStore,
	sessions store.SessionStore,
	verifications store.VerificationStore,
	totpStore store.TOTPStore,
	webauthnStore store.WebAuthnCredentialStore,
	recoveryCodeStore store.RecoveryCodeStore,
	anomalies store.AnomalyStore,
	ids security.IDGenerator,
	refreshGen token.TokenGenerator,
	jwtIssuer *token.JWTIssuer,
	pendingIssuer *token.MFAPendingIssuer,
	audit store.AuditStore,
	log logger.Logger,
	rawToken string,
	callerIP string,
	userAgent string,
	anomalyThresholds security.AnomalyThresholds,
) (Tokens, error) {
	vt, err := verifications.GetByTokenHash(ctx, token.HashToken(rawToken))
	if err != nil {
		return Tokens{}, ErrVerificationTokenInvalid
	}
	if vt.Purpose != store.PurposeMagicLink {
		return Tokens{}, ErrVerificationTokenInvalid
	}
	if vt.UsedAt != nil {
		return Tokens{}, ErrVerificationTokenInvalid
	}
	if time.Now().After(vt.ExpiresAt) {
		return Tokens{}, ErrVerificationTokenExpired
	}

	if err := verifications.MarkUsed(ctx, vt.ID); err != nil {
		log.Error("complete magic link: mark-used failed", map[string]string{"error": err.Error(), "user_id": vt.UserID})
	}

	user, err := users.GetByID(ctx, vt.UserID)
	if err != nil {
		return Tokens{}, err
	}

	return completePrimaryAuth(ctx, sessions, totpStore, webauthnStore, recoveryCodeStore, anomalies, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log, anomalyThresholds, user, callerIP, userAgent, nil)
}
