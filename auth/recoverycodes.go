package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/token"
)

// recoveryCodeCount is how many codes a single generation produces —
// fixed, not configurable, same reasoning as the other MFA constants:
// this is a security parameter with an established convention (most
// systems ship 8-10), not something worth exposing as a knob.
const recoveryCodeCount = 10

var (
	// ErrNoSecondFactorEnrolled is returned by GenerateRecoveryCodes
	// if the account has no confirmed TOTP secret and no registered
	// passkey — recovery codes exist to recover access to a second
	// factor, generating them for an account with none would be
	// meaningless (Login would never pause to ask for one).
	ErrNoSecondFactorEnrolled = errors.New("auth: no second factor is enrolled for this account")
	// ErrInvalidRecoveryCode covers a wrong code, an already-used one,
	// or an account with none generated at all — deliberately not
	// differentiated further, same enumeration-avoidance reasoning as
	// ErrInvalidTOTPCode.
	ErrInvalidRecoveryCode = errors.New("auth: invalid or already-used recovery code")
)

// GenerateRecoveryCodes creates a fresh batch of recoveryCodeCount
// single-use fallback codes for an already-authenticated user,
// replacing any existing batch — every previous code, used or not,
// stops working the moment a new batch is generated. The raw codes
// are returned exactly once here; the engine only ever stores their
// hashes and can never show them again afterward, same one-time-
// display convention as almost every real system that ships these.
// Requires the account to already have a confirmed TOTP secret or a
// registered passkey — see ErrNoSecondFactorEnrolled.
func GenerateRecoveryCodes(
	ctx context.Context,
	totpStore store.TOTPStore,
	webauthnStore store.WebAuthnCredentialStore,
	recoveryCodeStore store.RecoveryCodeStore,
	audit store.AuditStore,
	log logger.Logger,
	userID string,
) ([]string, error) {
	hasSecondFactor := false
	if totpStore != nil {
		secretRec, err := totpStore.GetByUserID(ctx, userID)
		if err == nil && secretRec.ConfirmedAt != nil {
			hasSecondFactor = true
		}
	}
	if !hasSecondFactor && webauthnStore != nil {
		creds, err := webauthnStore.ListByUser(ctx, userID)
		if err == nil && len(creds) > 0 {
			hasSecondFactor = true
		}
	}
	if !hasSecondFactor {
		return nil, ErrNoSecondFactorEnrolled
	}

	rawCodes := make([]string, recoveryCodeCount)
	toStore := make([]store.RecoveryCode, recoveryCodeCount)
	gen, err := token.NewCryptoRandTokenGenerator(5)
	if err != nil {
		return nil, err
	}
	for i := range rawCodes {
		raw, err := gen.New()
		if err != nil {
			return nil, err
		}
		formatted := raw[:5] + "-" + raw[5:]
		rawCodes[i] = formatted
		toStore[i] = store.RecoveryCode{CodeHash: hashRecoveryCode(formatted)}
	}

	if err := recoveryCodeStore.ReplaceAll(ctx, userID, toStore); err != nil {
		return nil, err
	}

	if err := audit.Record(ctx, store.AuditEvent{
		Type:   store.EventRecoveryCodesGenerated,
		UserID: userID,
	}); err != nil {
		log.Error("generate recovery codes: audit record failed", map[string]string{"error": err.Error(), "user_id": userID})
	}

	log.Info("recovery codes generated", map[string]string{"user_id": userID})
	return rawCodes, nil
}

// CompleteLoginWithRecoveryCode finishes a login that Login (or
// magic-link/OAuth login) paused with *ErrSecondFactorRequired, using
// one of the account's recovery codes instead of TOTP/a passkey. Each
// code works exactly once.
func CompleteLoginWithRecoveryCode(
	ctx context.Context,
	users store.UserStore,
	sessions store.SessionStore,
	recoveryCodeStore store.RecoveryCodeStore,
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

	if err := recoveryCodeStore.Consume(ctx, userID, hashRecoveryCode(code)); err != nil {
		if auditErr := audit.Record(ctx, store.AuditEvent{
			Type:   store.EventRecoveryCodeFailed,
			UserID: userID,
			IP:     callerIP,
		}); auditErr != nil {
			log.Error("complete recovery code login: audit record failed", map[string]string{"error": auditErr.Error()})
		}
		return Tokens{}, ErrInvalidRecoveryCode
	}

	user, err := users.GetByID(ctx, userID)
	if err != nil {
		return Tokens{}, err
	}

	if err := audit.Record(ctx, store.AuditEvent{
		Type:   store.EventRecoveryCodeUsed,
		UserID: userID,
		IP:     callerIP,
	}); err != nil {
		log.Error("complete recovery code login: audit record failed", map[string]string{"error": err.Error(), "user_id": userID})
	}

	return finishLogin(ctx, sessions, ids, refreshGen, jwtIssuer, audit, log, user, callerIP, userAgent, "recovery_code", nil)
}

// hashRecoveryCode normalizes user input (case, surrounding
// whitespace) before hashing, since people will retype these by hand
// and the formatting ("ABCDE-FGHIJ") is just for readability, not
// part of the actual secret value.
func hashRecoveryCode(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	return token.HashToken(normalized)
}
