package auth

import (
	"context"
	"encoding/json"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/token"
)

// webauthnUser adapts a store.User plus their existing passkeys to
// the webauthn.User interface the library requires. userID is used
// as the library's opaque "user handle" — our IDs are already
// UUIDv7, effectively random and unique, so there's no need for a
// separate generated handle the way some implementations use.
type webauthnUser struct {
	id          string
	email       string
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u *webauthnUser) WebAuthnName() string                       { return u.email }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.email }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

var _ webauthn.User = (*webauthnUser)(nil)

// loadWebAuthnUser builds a webauthnUser for userID, deserializing
// every stored credential blob back into the library's own type.
func loadWebAuthnUser(ctx context.Context, users store.UserStore, webauthnStore store.WebAuthnCredentialStore, userID string) (*webauthnUser, error) {
	user, err := users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	stored, err := webauthnStore.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(stored))
	for _, s := range stored {
		var c webauthn.Credential
		if err := json.Unmarshal(s.CredentialData, &c); err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return &webauthnUser{id: user.ID, email: user.Email, credentials: creds}, nil
}

// BeginRegisterPasskey starts registering a new passkey for an
// already-authenticated user. Returns the JSON-encoded creation
// options to forward to the browser's navigator.credentials.create()
// call, plus an opaque ceremony token the caller must pass back
// unmodified to FinishRegisterPasskey. The ceremony token is the
// library's own challenge state, JSON-encoded and encrypted with the
// same Encryptor used for TOTP secrets — no separate ephemeral store
// needed, the engine stays fully stateless between the two calls.
func BeginRegisterPasskey(
	ctx context.Context,
	users store.UserStore,
	webauthnStore store.WebAuthnCredentialStore,
	provider security.WebAuthnProvider,
	enc security.Encryptor,
	userID string,
) (creationOptionsJSON []byte, ceremonyToken string, err error) {
	user, err := loadWebAuthnUser(ctx, users, webauthnStore, userID)
	if err != nil {
		return nil, "", err
	}

	creation, session, err := provider.BeginRegistration(user)
	if err != nil {
		return nil, "", err
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, "", err
	}
	ceremonyToken, err = enc.Encrypt(string(sessionJSON))
	if err != nil {
		return nil, "", err
	}

	creationOptionsJSON, err = json.Marshal(creation)
	if err != nil {
		return nil, "", err
	}
	return creationOptionsJSON, ceremonyToken, nil
}

// FinishRegisterPasskey completes registration: decrypts ceremonyToken
// back into the ceremony's challenge state, verifies clientResponseJSON
// (the raw JSON body from navigator.credentials.create()) against it,
// and stores the resulting credential. nickname is a user-supplied,
// purely presentational label ("MacBook Touch ID").
func FinishRegisterPasskey(
	ctx context.Context,
	users store.UserStore,
	webauthnStore store.WebAuthnCredentialStore,
	provider security.WebAuthnProvider,
	enc security.Encryptor,
	ids security.IDGenerator,
	audit store.AuditStore,
	log logger.Logger,
	userID string,
	ceremonyToken string,
	clientResponseJSON []byte,
	nickname string,
) error {
	user, err := loadWebAuthnUser(ctx, users, webauthnStore, userID)
	if err != nil {
		return err
	}

	sessionJSON, err := enc.Decrypt(ceremonyToken)
	if err != nil {
		return ErrInvalidCeremonyToken
	}
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionJSON), &session); err != nil {
		return ErrInvalidCeremonyToken
	}

	cred, err := provider.FinishRegistration(user, session, clientResponseJSON)
	if err != nil {
		return ErrInvalidWebAuthnResponse
	}

	credentialData, err := json.Marshal(cred)
	if err != nil {
		return err
	}

	rowID, err := ids.New()
	if err != nil {
		return err
	}

	if err := webauthnStore.Add(ctx, store.WebAuthnCredential{
		ID:             rowID,
		UserID:         userID,
		CredentialID:   cred.ID,
		CredentialData: credentialData,
		Nickname:       nickname,
	}); err != nil {
		return err
	}

	if err := audit.Record(ctx, store.AuditEvent{
		Type:   store.EventWebAuthnRegistered,
		UserID: userID,
	}); err != nil {
		log.Error("finish register passkey: audit record failed", map[string]string{"error": err.Error(), "user_id": userID})
	}

	log.Info("passkey registered", map[string]string{"user_id": userID})
	return nil
}

// ListPasskeys returns every passkey registered to userID.
func ListPasskeys(ctx context.Context, webauthnStore store.WebAuthnCredentialStore, userID string) ([]store.WebAuthnCredential, error) {
	return webauthnStore.ListByUser(ctx, userID)
}

// DeletePasskey removes one passkey. Requires the current password as
// re-confirmation, same reasoning as DisableTOTP/ChangePassword — a
// stolen access token alone should never be enough to weaken an
// account's own auth requirements, regardless of how many other
// factors remain enrolled afterward.
func DeletePasskey(
	ctx context.Context,
	users store.UserStore,
	webauthnStore store.WebAuthnCredentialStore,
	hasher security.Hasher,
	audit store.AuditStore,
	log logger.Logger,
	userID string,
	credentialID []byte,
	currentPassword string,
) error {
	user, err := users.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if err := hasher.Compare(user.PasswordHash, currentPassword); err != nil {
		log.Warn("delete passkey: password mismatch", map[string]string{"user_id": userID})
		return ErrInvalidCredentials
	}

	if err := webauthnStore.Delete(ctx, userID, credentialID); err != nil {
		return err
	}

	if err := audit.Record(ctx, store.AuditEvent{
		Type:   store.EventWebAuthnRemoved,
		UserID: userID,
	}); err != nil {
		log.Error("delete passkey: audit record failed", map[string]string{"error": err.Error(), "user_id": userID})
	}

	log.Info("passkey removed", map[string]string{"user_id": userID})
	return nil
}

// BeginWebAuthnLogin starts the passkey half of a paused login.
// pendingToken must be the value from a prior *ErrSecondFactorRequired
// whose Methods included "webauthn". Returns JSON-encoded request
// options to forward to navigator.credentials.get(), plus an opaque
// ceremony token for CompleteLoginWithWebAuthn.
func BeginWebAuthnLogin(
	ctx context.Context,
	users store.UserStore,
	webauthnStore store.WebAuthnCredentialStore,
	provider security.WebAuthnProvider,
	enc security.Encryptor,
	pendingIssuer *token.MFAPendingIssuer,
	pendingToken string,
) (assertionOptionsJSON []byte, ceremonyToken string, err error) {
	userID, err := pendingIssuer.Verify(pendingToken)
	if err != nil {
		return nil, "", ErrInvalidPendingLogin
	}

	user, err := loadWebAuthnUser(ctx, users, webauthnStore, userID)
	if err != nil {
		return nil, "", err
	}
	if len(user.credentials) == 0 {
		return nil, "", ErrNoPasskeysEnrolled
	}

	assertion, session, err := provider.BeginLogin(user)
	if err != nil {
		return nil, "", err
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, "", err
	}
	ceremonyToken, err = enc.Encrypt(string(sessionJSON))
	if err != nil {
		return nil, "", err
	}

	assertionOptionsJSON, err = json.Marshal(assertion)
	if err != nil {
		return nil, "", err
	}
	return assertionOptionsJSON, ceremonyToken, nil
}

// CompleteLoginWithWebAuthn finishes a login that Login paused with
// *ErrSecondFactorRequired, via the passkey ceremony started by
// BeginWebAuthnLogin. pendingToken is re-verified here independently
// of BeginWebAuthnLogin's own verification — each call authenticates
// itself, callers must never assume state carries over implicitly.
func CompleteLoginWithWebAuthn(
	ctx context.Context,
	users store.UserStore,
	sessions store.SessionStore,
	webauthnStore store.WebAuthnCredentialStore,
	provider security.WebAuthnProvider,
	enc security.Encryptor,
	ids security.IDGenerator,
	refreshGen token.TokenGenerator,
	jwtIssuer *token.JWTIssuer,
	pendingIssuer *token.MFAPendingIssuer,
	audit store.AuditStore,
	log logger.Logger,
	pendingToken string,
	ceremonyToken string,
	clientResponseJSON []byte,
	callerIP string,
	userAgent string,
) (Tokens, error) {
	userID, err := pendingIssuer.Verify(pendingToken)
	if err != nil {
		return Tokens{}, ErrInvalidPendingLogin
	}

	user, err := loadWebAuthnUser(ctx, users, webauthnStore, userID)
	if err != nil {
		return Tokens{}, err
	}

	sessionJSON, err := enc.Decrypt(ceremonyToken)
	if err != nil {
		return Tokens{}, ErrInvalidCeremonyToken
	}
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionJSON), &session); err != nil {
		return Tokens{}, ErrInvalidCeremonyToken
	}

	updatedCred, err := provider.FinishLogin(user, session, clientResponseJSON)
	if err != nil {
		if auditErr := audit.Record(ctx, store.AuditEvent{
			Type:   store.EventWebAuthnChallengeFailed,
			UserID: userID,
			IP:     callerIP,
		}); auditErr != nil {
			log.Error("complete webauthn login: audit record failed", map[string]string{"error": auditErr.Error()})
		}
		return Tokens{}, ErrInvalidWebAuthnResponse
	}

	// Persist the authenticator's updated signature counter — this is
	// what makes cloned-authenticator detection possible on a future
	// login (the library rejects a non-advancing counter).
	credentialData, err := json.Marshal(updatedCred)
	if err != nil {
		return Tokens{}, err
	}
	if err := webauthnStore.Update(ctx, store.WebAuthnCredential{
		CredentialID:   updatedCred.ID,
		CredentialData: credentialData,
	}); err != nil {
		log.Error("complete webauthn login: failed to persist updated sign count", map[string]string{"error": err.Error(), "user_id": userID})
	}

	realUser, err := users.GetByID(ctx, userID)
	if err != nil {
		return Tokens{}, err
	}
	return finishLogin(ctx, sessions, ids, refreshGen, jwtIssuer, audit, log, realUser, callerIP, userAgent, "webauthn")
}
