package auth

import (
	"context"
	"errors"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/token"
)

// LoginWithOAuth is called by api AFTER it has already completed the
// provider's redirect/callback flow and confirmed the person's
// identity. The engine never talks to Google/GitHub itself, and never
// performs an HTTP redirect — by the time this is called, the OAuth
// dance is already over. provider is a plain string ("google",
// "github", or any other — the engine has no fixed list, adding a new
// provider is entirely api's job: register the app, implement its
// redirect/callback/token-exchange, then call this with its own
// provider string); externalID is the provider's own stable user ID,
// never its email.
//
// Three outcomes:
//  1. An OAuthIdentity already exists for (provider, externalID) ->
//     issue a session for its linked user.
//  2. No existing link, but a password-based account already exists
//     with this email -> return *ErrOAuthEmailConflict. Auto-linking
//     here was deliberately rejected as an account-takeover vector;
//     the caller must complete an explicit, confirmed linking step
//     (e.g. logging in with the password account first) before a
//     link is created.
//  3. Neither -> create a new User and OAuthIdentity, then issue a
//     session, same as a fresh signup.
//
// Either way, session issuance routes through the same
// completePrimaryAuth gate password/magic-link login use — an
// account with TOTP/a passkey enrolled pauses with
// *ErrSecondFactorRequired here too. Confirming an OAuth identity
// proves the primary factor, exactly like a correct password; it was
// never meant to bypass a confirmed second one, and until now it
// accidentally did.
func LoginWithOAuth(
	ctx context.Context,
	users store.UserStore,
	oauth store.OAuthStore,
	sessions store.SessionStore,
	totpStore store.TOTPStore,
	webauthnStore store.WebAuthnCredentialStore,
	recoveryCodeStore store.RecoveryCodeStore,
	ids security.IDGenerator,
	refreshGen token.TokenGenerator,
	jwtIssuer *token.JWTIssuer,
	pendingIssuer *token.MFAPendingIssuer,
	audit store.AuditStore,
	log logger.Logger,
	provider string,
	externalID string,
	email string,
	callerIP string,
	userAgent string,
) (Tokens, error) {
	identity, err := oauth.GetByProviderID(ctx, provider, externalID)
	switch {
	case err == nil:
		// Existing link — fall through to session issuance below.
	case errors.Is(err, store.ErrNotFound):
		user, existsErr := users.GetByEmail(ctx, email)
		if existsErr == nil {
			// A password-based account already owns this email, and
			// it isn't linked to this provider yet. Refuse to
			// auto-link; the caller must resolve this explicitly.
			log.Warn("oauth: email conflict with existing account", map[string]string{"provider": provider, "user_id": user.ID})
			return Tokens{}, &ErrOAuthEmailConflict{Email: email, Provider: provider}
		}
		if !errors.Is(existsErr, store.ErrNotFound) {
			return Tokens{}, existsErr
		}

		// Neither an existing link nor an existing account — create both.
		newUserID, idErr := ids.New()
		if idErr != nil {
			return Tokens{}, idErr
		}
		newUser := store.User{ID: newUserID, Email: email}
		if createErr := users.Create(ctx, newUser); createErr != nil {
			return Tokens{}, createErr
		}

		identityID, idErr := ids.New()
		if idErr != nil {
			return Tokens{}, idErr
		}
		identity = store.OAuthIdentity{
			ID:         identityID,
			UserID:     newUserID,
			Provider:   provider,
			ExternalID: externalID,
			Email:      email,
		}
		if linkErr := oauth.Link(ctx, identity); linkErr != nil {
			return Tokens{}, linkErr
		}

		if auditErr := audit.Record(ctx, store.AuditEvent{
			Type:     store.EventOAuthLinked,
			UserID:   newUserID,
			IP:       callerIP,
			Metadata: map[string]string{"provider": provider},
		}); auditErr != nil {
			log.Error("oauth: audit record failed", map[string]string{"error": auditErr.Error(), "user_id": newUserID})
		}
	default:
		return Tokens{}, err
	}

	user, err := users.GetByID(ctx, identity.UserID)
	if err != nil {
		return Tokens{}, err
	}
	return completePrimaryAuth(ctx, sessions, totpStore, webauthnStore, recoveryCodeStore, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log, user, callerIP, userAgent, map[string]string{"provider": provider})
}

// LinkOAuthIdentity attaches a confirmed external identity to an
// already-authenticated user. This is the resolution path for
// *ErrOAuthEmailConflict: api should require the caller to be
// currently logged in (e.g. via password) before calling this, so
// userID comes from a verified session/access token — never from the
// OAuth callback's email alone.
//
// Idempotent if the identity is already linked to this same user.
// Returns ErrOAuthIdentityAlreadyLinked if it's linked to a
// DIFFERENT user — never re-points an existing link, since that
// would let one account steal a provider identity another account
// already claimed.
func LinkOAuthIdentity(
	ctx context.Context,
	users store.UserStore,
	oauth store.OAuthStore,
	ids security.IDGenerator,
	audit store.AuditStore,
	log logger.Logger,
	userID string,
	provider string,
	externalID string,
	email string,
	callerIP string,
) error {
	if _, err := users.GetByID(ctx, userID); err != nil {
		return err
	}

	existing, err := oauth.GetByProviderID(ctx, provider, externalID)
	switch {
	case err == nil:
		if existing.UserID == userID {
			// Already linked to this same user — nothing to do.
			return nil
		}
		log.Warn("oauth: link rejected, identity already claimed", map[string]string{"provider": provider, "requesting_user_id": userID})
		return ErrOAuthIdentityAlreadyLinked
	case !errors.Is(err, store.ErrNotFound):
		return err
	}

	identityID, err := ids.New()
	if err != nil {
		return err
	}

	if err := oauth.Link(ctx, store.OAuthIdentity{
		ID:         identityID,
		UserID:     userID,
		Provider:   provider,
		ExternalID: externalID,
		Email:      email,
	}); err != nil {
		return err
	}

	if auditErr := audit.Record(ctx, store.AuditEvent{
		Type:     store.EventOAuthLinked,
		UserID:   userID,
		IP:       callerIP,
		Metadata: map[string]string{"provider": provider},
	}); auditErr != nil {
		log.Error("oauth: audit record failed", map[string]string{"error": auditErr.Error(), "user_id": userID})
	}

	log.Info("oauth: identity linked", map[string]string{"user_id": userID, "provider": provider})
	return nil
}
