package auth

import (
	"context"
	"errors"
	"time"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/notify"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/token"
)

var (
	ErrVerificationTokenInvalid = errors.New("auth: verification token invalid or already used")
	ErrVerificationTokenExpired = errors.New("auth: verification token expired")
)

// changeEmailTokenTTL is how long a "confirm your new email" link
// stays valid.
const changeEmailTokenTTL = 1 * time.Hour

// RequestEmailChange starts an email change. The user's email is NOT
// updated yet — a verification token is sent to the NEW address, and
// the change only takes effect once ConfirmEmailChange is called with
// a valid token. This prevents a user (or an attacker with a stolen
// access token) from silently redirecting an account to an email they
// don't actually control.
//
// NOTE: run your ValidateEmail check on newEmail BEFORE calling this.
func RequestEmailChange(
	ctx context.Context,
	users store.UserStore,
	verifications store.VerificationStore,
	sender notify.EmailSender,
	tokenGen token.TokenGenerator,
	ids security.IDGenerator,
	audit store.AuditStore,
	log logger.Logger,
	userID string,
	newEmail string,
) error {
	if _, err := users.GetByEmail(ctx, newEmail); err == nil {
		return ErrUserExists
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
		UserID:    userID,
		Purpose:   store.PurposeEmailChange,
		TokenHash: token.HashToken(rawToken),
		NewEmail:  newEmail,
		ExpiresAt: time.Now().Add(changeEmailTokenTTL),
	}
	if err := verifications.Create(ctx, vt); err != nil {
		return err
	}

	if err := sender.SendVerification(ctx, newEmail, rawToken); err != nil {
		return err
	}

	if err := audit.Record(ctx, store.AuditEvent{
		Type:   store.EventEmailChangeRequested,
		UserID: userID,
	}); err != nil {
		log.Error("email change request: audit record failed", map[string]string{"error": err.Error(), "user_id": userID})
	}

	log.Info("email change requested", map[string]string{"user_id": userID})
	return nil
}

// ConfirmEmailChange completes an email change using the raw token
// from the link sent to the new address.
func ConfirmEmailChange(
	ctx context.Context,
	users store.UserStore,
	verifications store.VerificationStore,
	audit store.AuditStore,
	log logger.Logger,
	rawToken string,
) error {
	vt, err := verifications.GetByTokenHash(ctx, token.HashToken(rawToken))
	if err != nil {
		return ErrVerificationTokenInvalid
	}
	if vt.Purpose != store.PurposeEmailChange {
		return ErrVerificationTokenInvalid
	}
	if vt.UsedAt != nil {
		return ErrVerificationTokenInvalid
	}
	if time.Now().After(vt.ExpiresAt) {
		return ErrVerificationTokenExpired
	}

	if err := users.UpdateEmail(ctx, vt.UserID, vt.NewEmail); err != nil {
		return err
	}
	if err := verifications.MarkUsed(ctx, vt.ID); err != nil {
		log.Error("confirm email change: mark-used failed", map[string]string{"error": err.Error(), "user_id": vt.UserID})
	}

	if err := audit.Record(ctx, store.AuditEvent{
		Type:   store.EventEmailChanged,
		UserID: vt.UserID,
	}); err != nil {
		log.Error("confirm email change: audit record failed", map[string]string{"error": err.Error(), "user_id": vt.UserID})
	}

	log.Info("email change confirmed", map[string]string{"user_id": vt.UserID})
	return nil
}
