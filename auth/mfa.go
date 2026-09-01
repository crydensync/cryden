package auth

import (
	"context"
	"time"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/token"
)

// EnrollTOTP begins TOTP enrollment for an already-authenticated user:
// generates a new secret, encrypts it at rest, and returns the
// otpauth:// URL for the caller to render as a QR code. The secret
// does NOT gate login yet — ConfirmTOTP must be called with a valid
// code first, proving the user actually captured the secret in their
// authenticator app. Re-enrolling an account that already has a
// confirmed secret is rejected; DisableTOTP must be called first.
func EnrollTOTP(
	ctx context.Context,
	users store.UserStore,
	totpStore store.TOTPStore,
	totpGen security.TOTPGenerator,
	enc security.Encryptor,
	issuerName string,
	userID string,
) (otpauthURL string, err error) {
	user, err := users.GetByID(ctx, userID)
	if err != nil {
		return "", err
	}

	if existing, getErr := totpStore.GetByUserID(ctx, userID); getErr == nil && existing.ConfirmedAt != nil {
		return "", ErrTOTPAlreadyEnabled
	}

	secret, url, err := totpGen.NewSecret(issuerName, user.Email)
	if err != nil {
		return "", err
	}

	encryptedSecret, err := enc.Encrypt(secret)
	if err != nil {
		return "", err
	}

	if err := totpStore.Upsert(ctx, store.TOTPSecret{
		UserID:          userID,
		EncryptedSecret: encryptedSecret,
	}); err != nil {
		return "", err
	}

	return url, nil
}

// ConfirmTOTP activates a pending TOTP enrollment once the user proves
// they've correctly captured the secret by submitting one valid code.
// A secret written by EnrollTOTP but never confirmed can never gate a
// login — this prevents an enrollment interrupted mid-flow (e.g. the
// browser closed before the QR code was scanned) from silently
// locking the user out on their next login.
func ConfirmTOTP(
	ctx context.Context,
	totpStore store.TOTPStore,
	totpGen security.TOTPGenerator,
	enc security.Encryptor,
	audit store.AuditStore,
	log logger.Logger,
	userID string,
	code string,
) error {
	secretRec, err := totpStore.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}
	if secretRec.ConfirmedAt != nil {
		return ErrTOTPAlreadyEnabled
	}

	plainSecret, err := enc.Decrypt(secretRec.EncryptedSecret)
	if err != nil {
		return err
	}

	if !totpGen.Validate(plainSecret, code, time.Now()) {
		return ErrInvalidTOTPCode
	}

	if err := totpStore.Confirm(ctx, userID); err != nil {
		return err
	}

	if err := audit.Record(ctx, store.AuditEvent{
		Type:   store.EventTOTPEnabled,
		UserID: userID,
	}); err != nil {
		log.Error("confirm totp: audit record failed", map[string]string{"error": err.Error(), "user_id": userID})
	}

	log.Info("totp enabled", map[string]string{"user_id": userID})
	return nil
}

// DisableTOTP removes a user's TOTP secret. Requires the current
// password as re-confirmation — same reasoning as
// ChangePassword/DeleteAccount: a stolen access token alone should
// never be sufficient to weaken an account's own auth requirements.
func DisableTOTP(
	ctx context.Context,
	users store.UserStore,
	totpStore store.TOTPStore,
	hasher security.Hasher,
	audit store.AuditStore,
	log logger.Logger,
	userID string,
	currentPassword string,
) error {
	user, err := users.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := hasher.Compare(user.PasswordHash, currentPassword); err != nil {
		log.Warn("disable totp: password mismatch", map[string]string{"user_id": userID})
		return ErrInvalidCredentials
	}

	if err := totpStore.Delete(ctx, userID); err != nil {
		return err
	}

	if err := audit.Record(ctx, store.AuditEvent{
		Type:   store.EventTOTPDisabled,
		UserID: userID,
	}); err != nil {
		log.Error("disable totp: audit record failed", map[string]string{"error": err.Error(), "user_id": userID})
	}

	log.Info("totp disabled", map[string]string{"user_id": userID})
	return nil
}

// CompleteLoginWithTOTP finishes a login that Login paused with
// *ErrSecondFactorRequired. pendingToken proves a correct password was
// already presented for the user encoded inside it; code is the
// current value from the user's authenticator app.
func CompleteLoginWithTOTP(
	ctx context.Context,
	users store.UserStore,
	sessions store.SessionStore,
	totpStore store.TOTPStore,
	totpGen security.TOTPGenerator,
	enc security.Encryptor,
	ids security.IDGenerator,
	refreshGen token.TokenGenerator,
	jwtIssuer *token.JWTIssuer,
	pendingIssuer *token.MFAPendingIssuer,
	audit store.AuditStore,
	log logger.Logger,
	pendingToken string,
	code string,
	callerIP string,
	userAgent string,
) (Tokens, error) {
	userID, err := pendingIssuer.Verify(pendingToken)
	if err != nil {
		return Tokens{}, ErrInvalidPendingLogin
	}

	user, err := users.GetByID(ctx, userID)
	if err != nil {
		return Tokens{}, err
	}

	secretRec, err := totpStore.GetByUserID(ctx, userID)
	if err != nil || secretRec.ConfirmedAt == nil {
		return Tokens{}, ErrTOTPNotEnabled
	}

	plainSecret, err := enc.Decrypt(secretRec.EncryptedSecret)
	if err != nil {
		return Tokens{}, err
	}

	if !totpGen.Validate(plainSecret, code, time.Now()) {
		if auditErr := audit.Record(ctx, store.AuditEvent{
			Type:   store.EventTOTPChallengeFailed,
			UserID: userID,
			IP:     callerIP,
		}); auditErr != nil {
			log.Error("complete totp login: audit record failed", map[string]string{"error": auditErr.Error()})
		}
		return Tokens{}, ErrInvalidTOTPCode
	}

	return finishLogin(ctx, sessions, ids, refreshGen, jwtIssuer, audit, log, user, callerIP, userAgent, "totp", nil)
}
