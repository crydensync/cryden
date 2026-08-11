// Package cryden is an embeddable, framework-agnostic authentication engine.
// Import this package only — internal packages (auth, token,
// store, security, session, logger) are implementation detail.
package cryden

import (
	"context"
	"errors"

	"github.com/crydensync/cryden/v2/auth"
	"github.com/crydensync/cryden/v2/session"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/token"
)

// Tokens is the access/refresh token pair returned by Login and
// RefreshToken.
type Tokens = auth.Tokens

// SignUp creates a new user. callerIP is required — used only for
// rate limiting and audit metadata, never inferred by the engine.
func SignUp(ctx context.Context, e *Engine, email, password, callerIP string) (store.User, error) {
	return auth.SignUp(ctx, e.users, e.hasher, e.ids, e.rateLimiter, e.audit, e.log, email, password, callerIP)
}

// Login authenticates a user and issues a new session. callerIP and
// userAgent are required, caller-supplied.
func Login(ctx context.Context, e *Engine, email, password, callerIP, userAgent string) (Tokens, error) {
	return auth.Login(ctx, e.users, e.sessions, e.hasher, e.ids, e.refreshGen, e.jwtIssuer, e.rateLimiter, e.audit, e.log, email, password, callerIP, userAgent, e.lockoutThreshold, e.lockoutDuration)
}

// ChangePassword requires the caller's current password as
// re-confirmation, and revokes all sessions on success.
func ChangePassword(ctx context.Context, e *Engine, userID, currentPassword, newPassword string) error {
	return auth.ChangePassword(ctx, e.users, e.sessions, e.hasher, e.audit, e.log, userID, currentPassword, newPassword)
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

// RevokeSession revokes a specific session. Verifies ownership before
// revoking.
func RevokeSession(ctx context.Context, e *Engine, sessionID, userID string) error {
	return session.Revoke(ctx, e.sessions, e.audit, e.log, sessionID, userID)
}
