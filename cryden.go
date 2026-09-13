// Package cryden is an embeddable, framework-agnostic authentication engine.
// Import this package only — internal packages (auth, token,
// store, security, session, logger) are implementation detail.
package cryden

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/crydensync/cryden/v2/auth"
	"github.com/crydensync/cryden/v2/session"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/token"
)

// Tokens is the access/refresh token pair returned by Login and
// RefreshToken.
type Tokens = auth.Tokens

// NamedSession is an active session plus its human-readable label,
// as returned by ListNamedSessions.
type NamedSession = session.NamedSession

// SignUp creates a new user. callerIP is required — used only for
// rate limiting and audit metadata, never inferred by the engine.
func SignUp(ctx context.Context, e *Engine, email, password, callerIP string) (store.User, error) {
	return auth.SignUp(ctx, e.users, e.hasher, e.ids, e.rateLimiter, e.breachChecker, e.audit, e.log, e.passwordPolicy, email, password, callerIP)
}

// Login authenticates a user and issues a new session. callerIP and
// userAgent are required, caller-supplied. If the account has any
// confirmed second factor (TOTP, a registered passkey, or both), no
// tokens are issued yet — Login returns *auth.ErrSecondFactorRequired
// (retrievable via errors.As) carrying a short-lived pending token
// and the list of enrolled methods; complete via CompleteLoginWithTOTP
// or BeginWebAuthnLogin/CompleteLoginWithWebAuthn accordingly.
func Login(ctx context.Context, e *Engine, email, password, callerIP, userAgent string) (Tokens, error) {
	return auth.Login(ctx, e.users, e.sessions, e.totp, e.webauthn, e.recoveryCodes, e.anomalies, e.hasher, e.ids, e.refreshGen, e.jwtIssuer, e.pendingIssuer, e.rateLimiter, e.audit, e.log, email, password, callerIP, userAgent, e.lockoutThreshold, e.lockoutDuration, e.anomalyThresholds, e.stuffingThresholds)
}

// ChangePassword requires the caller's current password as
// re-confirmation, and revokes all sessions on success.
func ChangePassword(ctx context.Context, e *Engine, userID, currentPassword, newPassword string) error {
	return auth.ChangePassword(ctx, e.users, e.sessions, e.hasher, e.breachChecker, e.audit, e.log, e.passwordPolicy, userID, currentPassword, newPassword)
}

// DeleteAccount requires the caller's current password as
// re-confirmation before this irreversible action.
func DeleteAccount(ctx context.Context, e *Engine, userID, currentPassword string) error {
	return auth.DeleteAccount(ctx, e.users, e.sessions, e.hasher, e.audit, e.log, userID, currentPassword)
}

// ErrEmailChangeNotConfigured is returned by RequestEmailChange if the
// Engine was built without Config.Verifications and Config.EmailSender set.
var ErrEmailChangeNotConfigured = errors.New("cryden: email change requires Config.Verifications and Config.EmailSender to be set")

// RequestEmailChange starts an email change — sends a verification
// link to newEmail. The email is not actually changed until
// ConfirmEmailChange is called with the resulting token.
func RequestEmailChange(ctx context.Context, e *Engine, userID, newEmail string) error {
	if e.verifications == nil || e.emailSender == nil {
		return ErrEmailChangeNotConfigured
	}
	return auth.RequestEmailChange(ctx, e.users, e.verifications, e.emailSender, e.refreshGen, e.ids, e.audit, e.log, userID, newEmail)
}

// ConfirmEmailChange completes an email change using the token from
// the verification link.
func ConfirmEmailChange(ctx context.Context, e *Engine, rawToken string) error {
	if e.verifications == nil {
		return ErrEmailChangeNotConfigured
	}
	return auth.ConfirmEmailChange(ctx, e.users, e.verifications, e.audit, e.log, rawToken)
}

// ErrOAuthNotConfigured is returned by LoginWithOAuth if the Engine
// was built without Config.OAuth set.
var ErrOAuthNotConfigured = errors.New("cryden: oauth login requires Config.OAuth to be set")

// LoginWithOAuth is called after api has already completed the
// provider's redirect/callback flow and confirmed the person's
// identity — the engine itself never talks to Google/GitHub or
// performs an HTTP redirect. Returns *auth.ErrOAuthEmailConflict
// (retrievable via errors.As) if externalID's email matches an
// existing password-based account that isn't linked yet; the engine
// deliberately does not auto-link in that case.
func LoginWithOAuth(ctx context.Context, e *Engine, provider, externalID, email, callerIP, userAgent string) (Tokens, error) {
	if e.oauth == nil {
		return Tokens{}, ErrOAuthNotConfigured
	}
	return auth.LoginWithOAuth(ctx, e.users, e.oauth, e.sessions, e.totp, e.webauthn, e.recoveryCodes, e.anomalies, e.ids, e.refreshGen, e.jwtIssuer, e.pendingIssuer, e.audit, e.log, provider, externalID, email, callerIP, userAgent, e.anomalyThresholds, e.stuffingThresholds)
}

// LinkOAuthIdentity attaches a confirmed external identity to an
// already-authenticated user. userID must come from a verified
// session/access token — this is the resolution path api should use
// after a *auth.ErrOAuthEmailConflict, once the caller has logged in
// with their password to prove ownership of the account.
func LinkOAuthIdentity(ctx context.Context, e *Engine, userID, provider, externalID, email, callerIP string) error {
	if e.oauth == nil {
		return ErrOAuthNotConfigured
	}
	return auth.LinkOAuthIdentity(ctx, e.users, e.oauth, e.ids, e.audit, e.log, userID, provider, externalID, email, callerIP)
}

// Logout revokes a single session. Verifies ownership before revoking.
func Logout(ctx context.Context, e *Engine, sessionID, userID string) error {
	return auth.Logout(ctx, e.sessions, e.audit, e.log, sessionID, userID)
}

// LogoutAll revokes every session belonging to userID.
func LogoutAll(ctx context.Context, e *Engine, userID string) error {
	return auth.LogoutAll(ctx, e.sessions, e.audit, e.log, userID)
}

// RefreshToken rotates a refresh token, issuing a new access/refresh
// pair. Returns auth.ErrTokenReused (wrapping token.ErrTokenReused) if
// reuse of an already-rotated token is detected — the entire session
// family has already been revoked by the time this returns.
func RefreshToken(ctx context.Context, e *Engine, rawRefreshToken string) (Tokens, error) {
	result, err := token.Rotate(ctx, e.sessions, e.refreshGen, e.ids, rawRefreshToken)
	if err != nil {
		if err == token.ErrTokenReused {
			if auditErr := e.audit.Record(ctx, store.AuditEvent{
				Type:   store.EventTokenReuseDetected,
				UserID: result.Session.UserID,
			}); auditErr != nil {
				e.log.Error("refresh: audit record failed", map[string]string{"error": auditErr.Error()})
			}
		}
		return Tokens{}, err
	}

	accessToken, err := e.jwtIssuer.Issue(result.Session.UserID)
	if err != nil {
		return Tokens{}, err
	}

	if auditErr := e.audit.Record(ctx, store.AuditEvent{
		Type:   store.EventTokenRotated,
		UserID: result.Session.UserID,
	}); auditErr != nil {
		e.log.Error("refresh: audit record failed", map[string]string{"error": auditErr.Error()})
	}

	return Tokens{AccessToken: accessToken, RefreshToken: result.RawToken}, nil
}

// VerifyToken validates an access token and returns the embedded
// user ID.
func VerifyToken(e *Engine, accessToken string) (string, error) {
	return e.jwtIssuer.Verify(accessToken)
}

// ListSessions returns all active sessions for a user.
func ListSessions(ctx context.Context, e *Engine, userID string) ([]store.Session, error) {
	return session.List(ctx, e.sessions, userID)
}

// GetUser looks up a user by email. Read-only, no side effects — safe
// to expose as a public facade function, unlike ChangePassword/
// DeleteAccount which require self-authentication. Added because
// admin tooling had no way to do this except reaching past the public
// facade into the store layer directly.
func GetUser(ctx context.Context, e *Engine, email string) (store.User, error) {
	return e.users.GetByEmail(ctx, email)
}

// ListPublicSessions is a redacted alternative to ListSessions,
// returning store.PublicSession (no TokenHash/FamilyID) instead of
// the full store.Session. Added alongside ListSessions, not as a
// replacement for it — existing callers of ListSessions are
// unaffected. Consumers building an HTTP-facing endpoint should
// prefer this over ListSessions plus their own hand-rolled DTO.
func ListPublicSessions(ctx context.Context, e *Engine, userID string) ([]store.PublicSession, error) {
	sessions, err := session.List(ctx, e.sessions, userID)
	if err != nil {
		return nil, err
	}
	out := make([]store.PublicSession, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, s.ToPublic())
	}
	return out, nil
}

// ListNamedSessions is ListPublicSessions with a human-readable label
// on each session — "Chrome on Windows — San Francisco, CA" instead of
// a bare session ID, for a settings page that expects someone to
// recognize their own devices and revoke the one they don't.
//
// Labels are derived on read from the IP and User-Agent already stored
// on each session, so this works retroactively on sessions created
// before it existed. The device half always resolves (to "Unknown
// device" at worst); the location half needs Config.Geolocator, and is
// simply omitted when that is unset or its lookup fails.
func ListNamedSessions(ctx context.Context, e *Engine, userID string) ([]NamedSession, error) {
	return session.ListNamed(ctx, e.sessions, e.geolocator, e.log, userID)
}

// RevokeSession revokes a specific session. Verifies ownership before
// revoking.
func RevokeSession(ctx context.Context, e *Engine, sessionID, userID string) error {
	return session.Revoke(ctx, e.sessions, e.audit, e.log, sessionID, userID)
}

// ErrTOTPNotConfigured is returned by every TOTP facade function
// below if the Engine was built without Config.TOTP (and
// Config.EncryptionKey) set.
var ErrTOTPNotConfigured = errors.New("cryden: TOTP requires Config.TOTP and Config.EncryptionKey to be set")

// EnrollTOTP begins 2FA enrollment for an already-authenticated user.
// Returns an otpauth:// URL — render it as a QR code for the user to
// scan with an authenticator app. The secret does not gate login yet;
// call ConfirmTOTP with a code from the app to activate it.
func EnrollTOTP(ctx context.Context, e *Engine, userID string) (string, error) {
	if e.totp == nil {
		return "", ErrTOTPNotConfigured
	}
	return auth.EnrollTOTP(ctx, e.users, e.totp, e.totpGen, e.encryptor, e.totpIssuerName, userID)
}

// ConfirmTOTP activates a pending TOTP enrollment once the user proves
// they've captured the secret by submitting one valid code from their
// authenticator app.
func ConfirmTOTP(ctx context.Context, e *Engine, userID, code string) error {
	if e.totp == nil {
		return ErrTOTPNotConfigured
	}
	return auth.ConfirmTOTP(ctx, e.totp, e.totpGen, e.encryptor, e.audit, e.log, userID, code)
}

// DisableTOTP removes 2FA from an account. Requires the current
// password as re-confirmation, same reasoning as
// ChangePassword/DeleteAccount.
func DisableTOTP(ctx context.Context, e *Engine, userID, currentPassword string) error {
	if e.totp == nil {
		return ErrTOTPNotConfigured
	}
	return auth.DisableTOTP(ctx, e.users, e.totp, e.hasher, e.audit, e.log, userID, currentPassword)
}

// CompleteLoginWithTOTP finishes a login that Login paused with
// *auth.ErrSecondFactorRequired (retrievable via errors.As). pendingToken is
// the value from that error; code is the current value from the
// user's authenticator app.
func CompleteLoginWithTOTP(ctx context.Context, e *Engine, pendingToken, code, callerIP, userAgent string) (Tokens, error) {
	if e.totp == nil {
		return Tokens{}, ErrTOTPNotConfigured
	}
	return auth.CompleteLoginWithTOTP(ctx, e.users, e.sessions, e.totp, e.totpGen, e.encryptor, e.ids, e.refreshGen, e.jwtIssuer, e.pendingIssuer, e.audit, e.log, pendingToken, code, callerIP, userAgent)
}

// ErrWebAuthnNotConfigured is returned by every passkey facade
// function below if the Engine was built without Config.WebAuthn set.
var ErrWebAuthnNotConfigured = errors.New("cryden: WebAuthn requires Config.WebAuthn (and its RP fields) to be set")

// Passkey is a public, storage-detail-free view of one registered
// passkey, for listing.
type Passkey struct {
	// CredentialID is base64url-encoded, matching how credential IDs
	// travel in the WebAuthn spec itself — pass it back as-is to
	// DeletePasskey.
	CredentialID string
	Nickname     string
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

// BeginRegisterPasskey starts registering a new passkey for an
// already-authenticated user. creationOptionsJSON is the raw JSON to
// forward to the browser's navigator.credentials.create() call;
// ceremonyToken must be passed back unmodified to FinishRegisterPasskey.
func BeginRegisterPasskey(ctx context.Context, e *Engine, userID string) (creationOptionsJSON []byte, ceremonyToken string, err error) {
	if e.webauthn == nil {
		return nil, "", ErrWebAuthnNotConfigured
	}
	return auth.BeginRegisterPasskey(ctx, e.users, e.webauthn, e.webauthnProvider, e.encryptor, userID)
}

// FinishRegisterPasskey completes registration. clientResponseJSON is
// the raw JSON body from navigator.credentials.create(); nickname is
// an optional user-supplied label ("MacBook Touch ID").
func FinishRegisterPasskey(ctx context.Context, e *Engine, userID, ceremonyToken string, clientResponseJSON []byte, nickname string) error {
	if e.webauthn == nil {
		return ErrWebAuthnNotConfigured
	}
	return auth.FinishRegisterPasskey(ctx, e.users, e.webauthn, e.webauthnProvider, e.encryptor, e.ids, e.audit, e.log, userID, ceremonyToken, clientResponseJSON, nickname)
}

// ListPasskeys returns every passkey registered to userID.
func ListPasskeys(ctx context.Context, e *Engine, userID string) ([]Passkey, error) {
	if e.webauthn == nil {
		return nil, ErrWebAuthnNotConfigured
	}
	creds, err := auth.ListPasskeys(ctx, e.webauthn, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Passkey, 0, len(creds))
	for _, c := range creds {
		out = append(out, Passkey{
			CredentialID: base64.URLEncoding.EncodeToString(c.CredentialID),
			Nickname:     c.Nickname,
			CreatedAt:    c.CreatedAt,
			LastUsedAt:   c.LastUsedAt,
		})
	}
	return out, nil
}

// DeletePasskey removes one passkey, identified by the CredentialID
// from ListPasskeys. Requires the current password as re-confirmation.
func DeletePasskey(ctx context.Context, e *Engine, userID, credentialID, currentPassword string) error {
	if e.webauthn == nil {
		return ErrWebAuthnNotConfigured
	}
	rawID, err := base64.URLEncoding.DecodeString(credentialID)
	if err != nil {
		return auth.ErrInvalidWebAuthnResponse
	}
	return auth.DeletePasskey(ctx, e.users, e.webauthn, e.hasher, e.audit, e.log, userID, rawID, currentPassword)
}

// BeginWebAuthnLogin starts the passkey half of a paused login.
// pendingToken must be the value from a prior *auth.ErrSecondFactorRequired
// whose Methods included "webauthn". assertionOptionsJSON is the raw
// JSON to forward to navigator.credentials.get(); ceremonyToken must
// be passed back unmodified to CompleteLoginWithWebAuthn.
func BeginWebAuthnLogin(ctx context.Context, e *Engine, pendingToken string) (assertionOptionsJSON []byte, ceremonyToken string, err error) {
	if e.webauthn == nil {
		return nil, "", ErrWebAuthnNotConfigured
	}
	return auth.BeginWebAuthnLogin(ctx, e.users, e.webauthn, e.webauthnProvider, e.encryptor, e.pendingIssuer, pendingToken)
}

// CompleteLoginWithWebAuthn finishes a login that Login paused with
// *auth.ErrSecondFactorRequired, via the passkey ceremony started by
// BeginWebAuthnLogin. clientResponseJSON is the raw JSON body from
// navigator.credentials.get().
func CompleteLoginWithWebAuthn(ctx context.Context, e *Engine, pendingToken, ceremonyToken string, clientResponseJSON []byte, callerIP, userAgent string) (Tokens, error) {
	if e.webauthn == nil {
		return Tokens{}, ErrWebAuthnNotConfigured
	}
	return auth.CompleteLoginWithWebAuthn(ctx, e.users, e.sessions, e.webauthn, e.webauthnProvider, e.encryptor, e.ids, e.refreshGen, e.jwtIssuer, e.pendingIssuer, e.audit, e.log, pendingToken, ceremonyToken, clientResponseJSON, callerIP, userAgent)
}

// ErrMagicLinkNotConfigured is returned by RequestMagicLink and
// CompleteMagicLink if the Engine was built without
// Config.MagicLinkSender set.
var ErrMagicLinkNotConfigured = errors.New("cryden: magic-link login requires Config.MagicLinkSender (and Config.Verifications) to be set")

// RequestMagicLink sends a passwordless login link to email, for an
// existing account only — this does not create accounts. Always
// returns nil for a nonexistent email (an email is only actually sent
// when the account exists) to avoid leaking which emails are
// registered; a genuine delivery failure for an existing account
// still propagates.
func RequestMagicLink(ctx context.Context, e *Engine, email, callerIP string) error {
	if e.magicLinkSender == nil {
		return ErrMagicLinkNotConfigured
	}
	return auth.RequestMagicLink(ctx, e.users, e.verifications, e.magicLinkSender, e.refreshGen, e.ids, e.rateLimiter, e.audit, e.log, email, callerIP)
}

// CompleteMagicLink logs in using the raw token from a link sent by
// RequestMagicLink. Like Login, it routes through the same
// second-factor gate — an account with TOTP/a passkey enrolled pauses
// with *auth.ErrSecondFactorRequired here exactly as it would after a
// correct password, retrievable via errors.As.
func CompleteMagicLink(ctx context.Context, e *Engine, rawToken, callerIP, userAgent string) (Tokens, error) {
	if e.magicLinkSender == nil {
		return Tokens{}, ErrMagicLinkNotConfigured
	}
	return auth.CompleteMagicLink(ctx, e.users, e.sessions, e.verifications, e.totp, e.webauthn, e.recoveryCodes, e.anomalies, e.ids, e.refreshGen, e.jwtIssuer, e.pendingIssuer, e.audit, e.log, rawToken, callerIP, userAgent, e.anomalyThresholds, e.stuffingThresholds)
}

// ErrRecoveryCodesNotConfigured is returned by GenerateRecoveryCodes
// and CompleteLoginWithRecoveryCode if the Engine was built without
// Config.RecoveryCodes set.
var ErrRecoveryCodesNotConfigured = errors.New("cryden: recovery codes require Config.RecoveryCodes to be set")

// GenerateRecoveryCodes creates a fresh batch of 10 single-use
// fallback codes for an already-authenticated user, replacing any
// existing batch. The raw codes are returned exactly once — show them
// to the user immediately, the engine can never retrieve them again
// afterward. Requires the account to already have a confirmed TOTP
// secret or a registered passkey.
func GenerateRecoveryCodes(ctx context.Context, e *Engine, userID string) ([]string, error) {
	if e.recoveryCodes == nil {
		return nil, ErrRecoveryCodesNotConfigured
	}
	return auth.GenerateRecoveryCodes(ctx, e.totp, e.webauthn, e.recoveryCodes, e.audit, e.log, userID)
}

// CompleteLoginWithRecoveryCode finishes a login that Login (or
// magic-link/OAuth login) paused with *auth.ErrSecondFactorRequired,
// using one of the account's recovery codes instead of TOTP/a
// passkey. Each code works exactly once.
func CompleteLoginWithRecoveryCode(ctx context.Context, e *Engine, pendingToken, code, callerIP, userAgent string) (Tokens, error) {
	if e.recoveryCodes == nil {
		return Tokens{}, ErrRecoveryCodesNotConfigured
	}
	return auth.CompleteLoginWithRecoveryCode(ctx, e.users, e.sessions, e.recoveryCodes, e.ids, e.refreshGen, e.jwtIssuer, e.pendingIssuer, e.audit, e.log, pendingToken, code, callerIP, userAgent)
}
