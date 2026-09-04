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
// totpStore and webauthnStore are optional (nil if not configured).
// If the account has any confirmed second factor — a confirmed TOTP
// secret, one or more registered passkeys, or both — Login does not
// issue tokens directly. It returns *ErrSecondFactorRequired carrying
// a short-lived pending token and the list of enrolled methods; the
// caller completes login via CompleteLoginWithTOTP or
// BeginWebAuthnLogin/CompleteLoginWithWebAuthn depending on which
// method the account has and the user picks.
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
	webauthnStore store.WebAuthnCredentialStore,
	recoveryCodeStore store.RecoveryCodeStore,
	anomalies store.AnomalyStore,
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
	anomalyThresholds security.AnomalyThresholds,
	stuffingThresholds security.CredentialStuffingThresholds,
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
		recordLoginFailure(ctx, audit, anomalies, log, stuffingThresholds, "", callerIP, userAgent, "no_such_user")
		return Tokens{}, ErrInvalidCredentials
	}

	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		log.Warn("login: attempt on locked account", map[string]string{"user_id": user.ID})
		return Tokens{}, ErrAccountLocked
	}

	if err := hasher.Compare(user.PasswordHash, password); err != nil {
		recordLoginFailure(ctx, audit, anomalies, log, stuffingThresholds, user.ID, callerIP, userAgent, "wrong_password")

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

	// The one moment the plaintext password and the stored hash are both
	// in hand, which is the only moment an out-of-date hash can be
	// rewritten. Never fails the login (see upgradePasswordHash).
	upgradePasswordHash(ctx, users, hasher, audit, log, user, password, callerIP)

	// Password verified. Route through the same second-factor gate
	// every primary authentication method uses (magic-link login goes
	// through this too) — a correct password only ever proves the
	// primary factor, never bypasses a confirmed second one.
	return completePrimaryAuth(ctx, sessions, totpStore, webauthnStore, recoveryCodeStore, anomalies, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log, anomalyThresholds, stuffingThresholds, user, callerIP, userAgent, nil)
}

// completePrimaryAuth is the shared tail of every primary
// authentication path (password login, magic-link login, OAuth login,
// and any future one) once the caller has independently established
// "this really is the account owner." It collects any confirmed
// second-factor methods the account has enrolled — a confirmed TOTP
// secret, one or more registered passkeys, or both — and either
// pauses with *ErrSecondFactorRequired or finishes the login
// directly. Centralizing this here means a new primary auth method
// can never accidentally skip the second-factor gate by reimplementing
// this check slightly differently. extraMetadata is passed straight
// through to finishLogin's audit event (e.g. OAuth's provider) — nil
// if there's nothing to add.
//
// "recovery_code" is only ever added to Methods alongside a real
// confirmed factor (totp/webauthn) — never on its own. Otherwise an
// account that disabled its last real second factor but still has
// unconsumed recovery codes sitting in storage would have those codes
// silently become a permanent standalone backdoor into the account,
// long after 2FA was supposedly turned off.
func completePrimaryAuth(
	ctx context.Context,
	sessions store.SessionStore,
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
	anomalyThresholds security.AnomalyThresholds,
	stuffingThresholds security.CredentialStuffingThresholds,
	user store.User,
	callerIP string,
	userAgent string,
	extraMetadata map[string]string,
) (Tokens, error) {
	// Runs here, in the one shared tail every primary auth method
	// reaches, for the same reason the second-factor gate does: a new
	// primary auth method can't accidentally skip it. Before the
	// second-factor branch below, so an account that pauses for TOTP is
	// still observed — the attempt already proved the primary factor,
	// which is what's being judged. Records and logs only; nothing it
	// finds changes what this function returns.
	detectLoginAnomalies(ctx, anomalies, sessions, audit, log, anomalyThresholds, user, callerIP, userAgent)

	// Credential stuffing is evaluated on successes as well as failures,
	// and this is the more important of the two: a login that SUCCEEDS
	// from an IP currently spraying many accounts means one of the
	// guesses landed. Ordering is not incidental — detectLoginAnomalies
	// records this attempt as it finishes, so the burst being measured
	// here includes it.
	detectCredentialStuffing(ctx, anomalies, audit, log, stuffingThresholds, user.ID, callerIP)

	var methods []string
	hasRealSecondFactor := false
	if totpStore != nil {
		secretRec, err := totpStore.GetByUserID(ctx, user.ID)
		if err == nil && secretRec.ConfirmedAt != nil {
			hasRealSecondFactor = true
			methods = append(methods, "totp")
		}
	}
	if webauthnStore != nil {
		creds, err := webauthnStore.ListByUser(ctx, user.ID)
		if err == nil && len(creds) > 0 {
			hasRealSecondFactor = true
			methods = append(methods, "webauthn")
		}
	}
	if hasRealSecondFactor && recoveryCodeStore != nil {
		count, err := recoveryCodeStore.CountUnused(ctx, user.ID)
		if err == nil && count > 0 {
			methods = append(methods, "recovery_code")
		}
	}
	if len(methods) > 0 {
		pendingToken, issueErr := pendingIssuer.Issue(user.ID)
		if issueErr != nil {
			return Tokens{}, issueErr
		}
		log.Info("login: primary factor verified, awaiting second factor", map[string]string{"user_id": user.ID})
		return Tokens{}, &ErrSecondFactorRequired{PendingToken: pendingToken, Methods: methods}
	}

	return finishLogin(ctx, sessions, ids, refreshGen, jwtIssuer, audit, log, user, callerIP, userAgent, "", extraMetadata)
}

// finishLogin issues a new session (access + refresh token pair) for
// an already-authenticated user. Shared by every path that reaches a
// completed login (password, magic-link, OAuth, and each
// second-factor completion) so they all create sessions identically.
// mfaMethod is recorded in the audit event's metadata ("" for no
// second factor). extraMetadata is merged in alongside it — e.g.
// LoginWithOAuth passes {"provider": provider} so the audit trail
// still shows which provider was used, the same detail it recorded
// before this became a shared helper. Pass nil if there's nothing to
// add.
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
	extraMetadata map[string]string,
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
	if mfaMethod != "" || len(extraMetadata) > 0 {
		metadata = make(map[string]string, len(extraMetadata)+1)
		for k, v := range extraMetadata {
			metadata[k] = v
		}
		if mfaMethod != "" {
			metadata["mfa"] = mfaMethod
		}
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

func recordLoginFailure(ctx context.Context, audit store.AuditStore, anomalies store.AnomalyStore, log logger.Logger, stuffingThresholds security.CredentialStuffingThresholds, userID, callerIP, userAgent, reason string) {
	if err := audit.Record(ctx, store.AuditEvent{
		Type:     store.EventLoginFailed,
		UserID:   userID,
		IP:       callerIP,
		Metadata: map[string]string{"reason": reason},
	}); err != nil {
		log.Error("login: audit record failed", map[string]string{"error": err.Error()})
	}
	// The same failure also feeds anomaly detection's velocity counts —
	// per-user AND per-IP, which is why an unknown-email failure (empty
	// userID) is still worth recording: it's real evidence about the IP.
	RecordLoginAttempt(ctx, anomalies, log, store.LoginAttempt{
		UserID:    userID,
		IP:        callerIP,
		UserAgent: userAgent,
		Outcome:   store.OutcomeFailure,
	})
	// After the attempt above is recorded, never before: this failure is
	// part of the burst being judged. Failures are where a spray is
	// visible at all — an attacker working through a list of accounts
	// they have no valid password for produces nothing but these.
	detectCredentialStuffing(ctx, anomalies, audit, log, stuffingThresholds, userID, callerIP)

	log.Warn("login: failed attempt", map[string]string{"ip": callerIP, "reason": reason})
}
