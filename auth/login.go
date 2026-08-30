package auth

import (
	"context"
	"strconv"
	"time"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/token"
)

// Login authenticates a user and issues a new session (access + refresh
// token pair). callerIP and userAgent are required, caller-supplied —
// never inferred inside the engine.
//
// totpStore and pendingIssuer are optional (nil if Config.TOTP isn't
// set). If the account has a confirmed TOTP secret, Login does not
// issue tokens directly — it returns *ErrTOTPRequired carrying a
// short-lived pending token; the caller must then call
// CompleteLoginWithTOTP with that token plus a code.
//
// lockoutThreshold and lockoutDuration configure account lockout: after
// lockoutThreshold consecutive failed attempts, the account is locked
// (persistent, DB-backed — survives restarts, correct across multiple
// instances, unlike the in-memory rate limiter) for lockoutDuration.
func Login(
	ctx context.Context,
	users store.UserStore,
	sessions store.SessionStore,
	totpStore store.TOTPStore,
	hasher security.Hasher,
	ids security.IDGenerator,
	refreshGen token.TokenGenerator,
	jwtIssuer *token.JWTIssuer,
	pendingIssuer *token.MFAPendingIssuer,
	limiter security.RateLimiter,
	audit store.AuditStore,
	log logger.Logger,
	email string,
	password string,
	callerIP string,
	userAgent string,
	lockoutThreshold int,
	lockoutDuration time.Duration,
) (Tokens, error) {
	allowed, err := limiter.Allow(ctx, "login:"+callerIP+":"+email)
	if err != nil {
		log.Error("login: rate limiter error", map[string]string{"error": err.Error()})
		return Tokens{}, err
	}
	if !allowed {
		log.Warn("login: rate limited", map[string]string{"ip": callerIP})
		return Tokens{}, ErrRateLimited
	}

	user, err := users.GetByEmail(ctx, email)
	if err != nil {
		// Still pay bcrypt's cost even though there's no hash to
		// check against — hasher.Hash runs the same underlying cost
		// function as hasher.Compare. Without this, a nonexistent-
		// email response returns measurably faster than a wrong-
		// password one, letting an attacker enumerate registered
		// emails by timing alone even though the returned error is
		// identical either way.
		_, _ = hasher.Hash(password)
		recordLoginFailure(ctx, audit, log, "", callerIP, "no_such_user")
		return Tokens{}, ErrInvalidCredentials
	}

	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		log.Warn("login: attempt on locked account", map[string]string{"user_id": user.ID})
		return Tokens{}, ErrAccountLocked
	}

	if err := hasher.Compare(user.PasswordHash, password); err != nil {
		recordLoginFailure(ctx, audit, log, user.ID, callerIP, "wrong_password")

		attempts, incErr := users.IncrementFailedAttempts(ctx, user.ID)
		if incErr != nil {
			log.Error("login: failed-attempt increment error", map[string]string{"error": incErr.Error(), "user_id": user.ID})
		} else if attempts >= lockoutThreshold {
			until := time.Now().Add(lockoutDuration)
			if lockErr := users.LockAccount(ctx, user.ID, until); lockErr != nil {
				log.Error("login: lock account error", map[string]string{"error": lockErr.Error(), "user_id": user.ID})
			} else {
				if auditErr := audit.Record(ctx, store.AuditEvent{
					Type:   store.EventAccountLocked,
					UserID: user.ID,
					IP:     callerIP,
				}); auditErr != nil {
					log.Error("login: audit record failed", map[string]string{"error": auditErr.Error()})
				}
				log.Warn("login: account locked after repeated failures", map[string]string{"user_id": user.ID, "attempts": strconv.Itoa(attempts)})
			}
		}

		return Tokens{}, ErrInvalidCredentials
	}

	if err := users.ResetFailedAttempts(ctx, user.ID); err != nil {
		log.Error("login: reset failed-attempts error", map[string]string{"error": err.Error(), "user_id": user.ID})
	}

	// Password verified. If this account has a confirmed TOTP secret,
	// pause here instead of issuing tokens — a correct password alone
	// is no longer sufficient to complete login.
	if totpStore != nil {
		secretRec, err := totpStore.GetByUserID(ctx, user.ID)
		if err == nil && secretRec.ConfirmedAt != nil {
			pendingToken, issueErr := pendingIssuer.Issue(user.ID)
			if issueErr != nil {
				return Tokens{}, issueErr
			}
			log.Info("login: password verified, awaiting TOTP", map[string]string{"user_id": user.ID})
			return Tokens{}, &ErrTOTPRequired{PendingToken: pendingToken}
		}
	}

	return finishLogin(ctx, sessions, ids, refreshGen, jwtIssuer, audit, log, user, callerIP, userAgent, "")
}

// finishLogin issues a new session (access + refresh token pair) for
// an already-authenticated user. Shared by Login (password-only
// accounts) and CompleteLoginWithTOTP (accounts with 2FA) so both
// paths create sessions identically — a second factor changes how a
// caller gets here, never what a completed login produces. mfaMethod
// is recorded in the audit event's metadata ("" for password-only).
func finishLogin(
	ctx context.Context,
	sessions store.SessionStore,
	ids security.IDGenerator,
	refreshGen token.TokenGenerator,
	jwtIssuer *token.JWTIssuer,
	audit store.AuditStore,
	log logger.Logger,
	user store.User,
	callerIP string,
	userAgent string,
	mfaMethod string,
) (Tokens, error) {
	sessionID, err := ids.New()
	if err != nil {
		return Tokens{}, err
	}

	rawRefresh, err := refreshGen.New()
	if err != nil {
		return Tokens{}, err
	}

	// A fresh login starts a new rotation family — the session's own
	// ID doubles as its family_id at creation time.
	session := store.Session{
		ID:        sessionID,
		FamilyID:  sessionID,
		UserID:    user.ID,
		TokenHash: token.HashToken(rawRefresh),
		IP:        callerIP,
		UserAgent: userAgent,
	}

	if err := sessions.Create(ctx, session); err != nil {
		return Tokens{}, err
	}

	accessToken, err := jwtIssuer.Issue(user.ID)
	if err != nil {
		return Tokens{}, err
	}

	var metadata map[string]string
	if mfaMethod != "" {
		metadata = map[string]string{"mfa": mfaMethod}
	}
	if err := audit.Record(ctx, store.AuditEvent{
		Type:     store.EventLoginSuccess,
		UserID:   user.ID,
		IP:       callerIP,
		Metadata: metadata,
	}); err != nil {
		log.Error("login: audit record failed", map[string]string{"error": err.Error(), "user_id": user.ID})
	}

	log.Info("login: completed", map[string]string{"user_id": user.ID})

	return Tokens{AccessToken: accessToken, RefreshToken: rawRefresh}, nil
}

func recordLoginFailure(ctx context.Context, audit store.AuditStore, log logger.Logger, userID, callerIP, reason string) {
	if err := audit.Record(ctx, store.AuditEvent{
		Type:     store.EventLoginFailed,
		UserID:   userID,
		IP:       callerIP,
		Metadata: map[string]string{"reason": reason},
	}); err != nil {
		log.Error("login: audit record failed", map[string]string{"error": err.Error()})
	}
	log.Warn("login: failed attempt", map[string]string{"ip": callerIP, "reason": reason})
}
