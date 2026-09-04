package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"
	"github.com/pquerna/otp/totp"
)

func newTOTPLoginTestDeps(t *testing.T) (*memory.UserStore, *memory.SessionStore, *memory.TOTPStore, *memory.AuditStore, security.Hasher, security.IDGenerator, token.TokenGenerator, *token.JWTIssuer, *token.MFAPendingIssuer, security.RateLimiter, security.TOTPGenerator, security.Encryptor) {
	t.Helper()
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	totpStore := memory.NewTOTPStore()
	audit := memory.NewAuditStore()
	hasher, _ := security.NewBcryptHasher(4)
	ids := security.NewUUIDv7Generator()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")
	limiter := security.NewInMemoryRateLimiter(1000, time.Minute)
	totpGen := security.NewPquernaTOTPGenerator()
	enc, _ := security.NewAESGCMEncryptor("test-encryption-key")
	return users, sessions, totpStore, audit, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, totpGen, enc
}

// enrollAndConfirm is a test helper that fully enrolls and confirms
// TOTP for a user, returning the plaintext secret so tests can
// generate real codes against it.
func enrollAndConfirm(t *testing.T, ctx context.Context, users *memory.UserStore, totpStore *memory.TOTPStore, audit *memory.AuditStore, totpGen security.TOTPGenerator, enc security.Encryptor, userID string) string {
	t.Helper()
	log := testLogger{}
	if _, err := EnrollTOTP(ctx, users, totpStore, totpGen, enc, "CrydenSync", userID); err != nil {
		t.Fatalf("enroll failed: %v", err)
	}
	secretRec, _ := totpStore.GetByUserID(ctx, userID)
	plainSecret, _ := enc.Decrypt(secretRec.EncryptedSecret)
	code, _ := totp.GenerateCode(plainSecret, time.Now())
	if err := ConfirmTOTP(ctx, totpStore, totpGen, enc, audit, log, userID, code); err != nil {
		t.Fatalf("confirm failed: %v", err)
	}
	return plainSecret
}

func TestLogin_WithConfirmedTOTPReturnsErrSecondFactorRequired(t *testing.T) {
	users, sessions, totpStore, audit, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, totpGen, enc := newTOTPLoginTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	enrollAndConfirm(t, ctx, users, totpStore, audit, totpGen, enc, "user-1")

	tokens, err := Login(ctx, users, sessions, totpStore, nil, nil, nil, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, audit, log,
		"raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent", 5, time.Minute, noAnomalyThresholds)

	var totpRequired *ErrSecondFactorRequired
	if !errors.As(err, &totpRequired) {
		t.Fatalf("expected *ErrSecondFactorRequired, got %v", err)
	}
	if totpRequired.PendingToken == "" {
		t.Error("expected a non-empty pending token")
	}
	if tokens.AccessToken != "" || tokens.RefreshToken != "" {
		t.Error("expected no tokens to be issued before the second factor is completed")
	}
}

func TestLogin_WithoutTOTPConfiguredIssuesTokensDirectly(t *testing.T) {
	// A user with no TOTP secret at all must log in exactly as before
	// — the feature is purely additive per-account, never a default.
	users, sessions, totpStore, audit, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, _, _ := newTOTPLoginTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))

	tokens, err := Login(ctx, users, sessions, totpStore, nil, nil, nil, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, audit, log,
		"raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent", 5, time.Minute, noAnomalyThresholds)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Error("expected tokens to be issued directly when TOTP isn't enrolled")
	}
}

func TestLogin_UnconfirmedTOTPDoesNotGateLogin(t *testing.T) {
	// Enrollment alone (never confirmed) must never block a login —
	// otherwise an interrupted enrollment flow would lock the user
	// out of their own account.
	users, sessions, totpStore, audit, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, totpGen, enc := newTOTPLoginTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	if _, err := EnrollTOTP(ctx, users, totpStore, totpGen, enc, "CrydenSync", "user-1"); err != nil {
		t.Fatalf("enroll failed: %v", err)
	}

	tokens, err := Login(ctx, users, sessions, totpStore, nil, nil, nil, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, audit, log,
		"raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent", 5, time.Minute, noAnomalyThresholds)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Error("expected tokens to be issued — unconfirmed TOTP must not gate login")
	}
}

func TestCompleteLoginWithTOTP_CorrectCodeIssuesTokens(t *testing.T) {
	users, sessions, totpStore, audit, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, totpGen, enc := newTOTPLoginTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	secret := enrollAndConfirm(t, ctx, users, totpStore, audit, totpGen, enc, "user-1")

	_, err := Login(ctx, users, sessions, totpStore, nil, nil, nil, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, audit, log,
		"raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent", 5, time.Minute, noAnomalyThresholds)
	var totpRequired *ErrSecondFactorRequired
	if !errors.As(err, &totpRequired) {
		t.Fatalf("expected *ErrSecondFactorRequired, got %v", err)
	}

	code, _ := totp.GenerateCode(secret, time.Now())
	tokens, err := CompleteLoginWithTOTP(ctx, users, sessions, totpStore, totpGen, enc, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log,
		totpRequired.PendingToken, code, "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Error("expected both tokens to be populated")
	}
}

func TestCompleteLoginWithTOTP_WrongCodeRejected(t *testing.T) {
	users, sessions, totpStore, audit, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, totpGen, enc := newTOTPLoginTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	enrollAndConfirm(t, ctx, users, totpStore, audit, totpGen, enc, "user-1")

	_, err := Login(ctx, users, sessions, totpStore, nil, nil, nil, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, audit, log,
		"raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent", 5, time.Minute, noAnomalyThresholds)
	var totpRequired *ErrSecondFactorRequired
	errors.As(err, &totpRequired)

	_, err = CompleteLoginWithTOTP(ctx, users, sessions, totpStore, totpGen, enc, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log,
		totpRequired.PendingToken, "000000", "1.2.3.4", "test-agent")
	if err != ErrInvalidTOTPCode {
		t.Errorf("expected ErrInvalidTOTPCode, got %v", err)
	}
}

func TestCompleteLoginWithTOTP_TamperedPendingTokenRejected(t *testing.T) {
	users, sessions, totpStore, audit, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, totpGen, enc := newTOTPLoginTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	secret := enrollAndConfirm(t, ctx, users, totpStore, audit, totpGen, enc, "user-1")
	code, _ := totp.GenerateCode(secret, time.Now())

	_, err := CompleteLoginWithTOTP(ctx, users, sessions, totpStore, totpGen, enc, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log,
		"not-a-real-token", code, "1.2.3.4", "test-agent")
	if err != ErrInvalidPendingLogin {
		t.Errorf("expected ErrInvalidPendingLogin, got %v", err)
	}
	_ = limiter
}

func TestCompleteLoginWithTOTP_RejectsARealAccessTokenAsPendingToken(t *testing.T) {
	// An access token and a pending-login token are both signed with
	// the same secret. Verify's "typ" claim check is the only thing
	// standing between "logged in" and "still needs a second factor"
	// — this test exists specifically to catch a regression there.
	users, sessions, totpStore, audit, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, totpGen, enc := newTOTPLoginTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	secret := enrollAndConfirm(t, ctx, users, totpStore, audit, totpGen, enc, "user-1")
	code, _ := totp.GenerateCode(secret, time.Now())

	realAccessToken, _ := jwtIssuer.Issue("user-1")

	_, err := CompleteLoginWithTOTP(ctx, users, sessions, totpStore, totpGen, enc, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log,
		realAccessToken, code, "1.2.3.4", "test-agent")
	if err != ErrInvalidPendingLogin {
		t.Errorf("expected ErrInvalidPendingLogin when handed a real access token, got %v", err)
	}

	_ = limiter
}
