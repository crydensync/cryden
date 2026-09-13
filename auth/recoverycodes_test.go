package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"
)

func newRecoveryCodeTestDeps(t *testing.T) (*memory.UserStore, *memory.TOTPStore, *memory.RecoveryCodeStore, *memory.AuditStore, security.TOTPGenerator, security.Encryptor) {
	t.Helper()
	users := memory.NewUserStore()
	totpStore := memory.NewTOTPStore()
	recoveryCodeStore := memory.NewRecoveryCodeStore()
	audit := memory.NewAuditStore()
	totpGen := security.NewPquernaTOTPGenerator()
	enc, _ := security.NewAESGCMEncryptor("test-encryption-key")
	return users, totpStore, recoveryCodeStore, audit, totpGen, enc
}

func TestGenerateRecoveryCodes_RejectsAccountWithNoSecondFactor(t *testing.T) {
	users, totpStore, recoveryCodeStore, audit, _, _ := newRecoveryCodeTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hasher, _ := security.NewBcryptHasher(4)
	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))

	_, err := GenerateRecoveryCodes(ctx, totpStore, nil, recoveryCodeStore, audit, log, "user-1")
	if err != ErrNoSecondFactorEnrolled {
		t.Errorf("expected ErrNoSecondFactorEnrolled, got %v", err)
	}
}

func TestGenerateRecoveryCodes_ProducesTenUniqueCodes(t *testing.T) {
	users, totpStore, recoveryCodeStore, audit, totpGen, enc := newRecoveryCodeTestDeps(t)
	ctx := context.Background()

	hasher, _ := security.NewBcryptHasher(4)
	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	enrollAndConfirm(t, ctx, users, totpStore, audit, totpGen, enc, "user-1")

	codes, err := GenerateRecoveryCodes(ctx, totpStore, nil, recoveryCodeStore, audit, testLogger{}, "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(codes) != recoveryCodeCount {
		t.Fatalf("expected %d codes, got %d", recoveryCodeCount, len(codes))
	}
	seen := make(map[string]bool)
	for _, c := range codes {
		if seen[c] {
			t.Errorf("duplicate code generated: %q", c)
		}
		seen[c] = true
	}

	count, err := recoveryCodeStore.CountUnused(ctx, "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != recoveryCodeCount {
		t.Errorf("expected %d unused codes stored, got %d", recoveryCodeCount, count)
	}
}

func TestGenerateRecoveryCodes_RegeneratingInvalidatesThePreviousBatch(t *testing.T) {
	users, totpStore, recoveryCodeStore, audit, totpGen, enc := newRecoveryCodeTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hasher, _ := security.NewBcryptHasher(4)
	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	enrollAndConfirm(t, ctx, users, totpStore, audit, totpGen, enc, "user-1")

	firstBatch, _ := GenerateRecoveryCodes(ctx, totpStore, nil, recoveryCodeStore, audit, log, "user-1")
	_, err := GenerateRecoveryCodes(ctx, totpStore, nil, recoveryCodeStore, audit, log, "user-1")
	if err != nil {
		t.Fatalf("unexpected error regenerating: %v", err)
	}

	// A code from the first batch must no longer be consumable.
	err = recoveryCodeStore.Consume(ctx, "user-1", hashRecoveryCode(firstBatch[0]))
	if err == nil {
		t.Error("expected a code from the invalidated first batch to be rejected")
	}
}

func TestCompleteLoginWithRecoveryCode_ValidCodeIssuesTokensAndIsSingleUse(t *testing.T) {
	users, totpStore, recoveryCodeStore, audit, totpGen, enc := newRecoveryCodeTestDeps(t)
	log := testLogger{}
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	ids := security.NewUUIDv7Generator()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")

	hasher, _ := security.NewBcryptHasher(4)
	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	enrollAndConfirm(t, ctx, users, totpStore, audit, totpGen, enc, "user-1")
	codes, _ := GenerateRecoveryCodes(ctx, totpStore, nil, recoveryCodeStore, audit, log, "user-1")

	pendingToken, _ := pendingIssuer.Issue("user-1")

	tokens, err := CompleteLoginWithRecoveryCode(ctx, users, sessions, recoveryCodeStore, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log, pendingToken, codes[0], "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Error("expected both tokens to be populated")
	}

	// The same code must not work a second time.
	pendingToken2, _ := pendingIssuer.Issue("user-1")
	_, err = CompleteLoginWithRecoveryCode(ctx, users, sessions, recoveryCodeStore, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log, pendingToken2, codes[0], "1.2.3.4", "test-agent")
	if err != ErrInvalidRecoveryCode {
		t.Errorf("expected ErrInvalidRecoveryCode on reuse, got %v", err)
	}
}

func TestCompleteLoginWithRecoveryCode_CaseAndWhitespaceInsensitive(t *testing.T) {
	users, totpStore, recoveryCodeStore, audit, totpGen, enc := newRecoveryCodeTestDeps(t)
	log := testLogger{}
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	ids := security.NewUUIDv7Generator()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")

	hasher, _ := security.NewBcryptHasher(4)
	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	enrollAndConfirm(t, ctx, users, totpStore, audit, totpGen, enc, "user-1")
	codes, _ := GenerateRecoveryCodes(ctx, totpStore, nil, recoveryCodeStore, audit, log, "user-1")

	pendingToken, _ := pendingIssuer.Issue("user-1")
	messyInput := "  " + strings.ToUpper(codes[0]) + "  "

	_, err := CompleteLoginWithRecoveryCode(ctx, users, sessions, recoveryCodeStore, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log, pendingToken, messyInput, "1.2.3.4", "test-agent")
	if err != nil {
		t.Errorf("expected an uppercased/padded code to still work, got %v", err)
	}
}

func TestCompleteLoginWithRecoveryCode_WrongCodeRejected(t *testing.T) {
	users, totpStore, recoveryCodeStore, audit, totpGen, enc := newRecoveryCodeTestDeps(t)
	log := testLogger{}
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	ids := security.NewUUIDv7Generator()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")

	hasher, _ := security.NewBcryptHasher(4)
	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	enrollAndConfirm(t, ctx, users, totpStore, audit, totpGen, enc, "user-1")
	GenerateRecoveryCodes(ctx, totpStore, nil, recoveryCodeStore, audit, log, "user-1")

	pendingToken, _ := pendingIssuer.Issue("user-1")
	_, err := CompleteLoginWithRecoveryCode(ctx, users, sessions, recoveryCodeStore, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log, pendingToken, "wrong-code", "1.2.3.4", "test-agent")
	if err != ErrInvalidRecoveryCode {
		t.Errorf("expected ErrInvalidRecoveryCode, got %v", err)
	}
}

func TestLogin_RecoveryCodeNeverAdvertisedWithoutARealSecondFactor(t *testing.T) {
	// The critical safety property: unconsumed recovery codes must
	// never become a standalone login gate on their own. Simulates an
	// account that has recovery codes in storage (e.g. left over from
	// before TOTP was disabled) but no confirmed TOTP/passkey.
	users, totpStore, recoveryCodeStore, audit, totpGen, enc := newRecoveryCodeTestDeps(t)
	log := testLogger{}
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	webauthnStore := memory.NewWebAuthnStore()
	ids := security.NewUUIDv7Generator()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")
	limiter := security.NewInMemoryRateLimiter(1000, time.Minute)
	hasher, _ := security.NewBcryptHasher(4)

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	enrollAndConfirm(t, ctx, users, totpStore, audit, totpGen, enc, "user-1")
	GenerateRecoveryCodes(ctx, totpStore, nil, recoveryCodeStore, audit, log, "user-1")

	// Now disable TOTP (simulated directly via store, bypassing
	// DisableTOTP's password check — this test only cares about
	// Login's behavior once no real factor remains).
	totpStore.Delete(ctx, "user-1")

	tokens, err := Login(ctx, users, sessions, totpStore, webauthnStore, recoveryCodeStore, nil, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, audit, log,
		"raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent", 5, time.Minute, noAnomalyThresholds, noStuffingThresholds)
	if err != nil {
		t.Fatalf("expected direct login once no real second factor remains, got error: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Error("expected tokens to be issued directly — leftover recovery codes must never gate login alone")
	}
}

func TestLogin_ReportsRecoveryCodeAlongsideTOTP(t *testing.T) {
	users, totpStore, recoveryCodeStore, audit, totpGen, enc := newRecoveryCodeTestDeps(t)
	log := testLogger{}
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	webauthnStore := memory.NewWebAuthnStore()
	ids := security.NewUUIDv7Generator()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")
	limiter := security.NewInMemoryRateLimiter(1000, time.Minute)
	hasher, _ := security.NewBcryptHasher(4)

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	enrollAndConfirm(t, ctx, users, totpStore, audit, totpGen, enc, "user-1")
	GenerateRecoveryCodes(ctx, totpStore, nil, recoveryCodeStore, audit, log, "user-1")

	_, err := Login(ctx, users, sessions, totpStore, webauthnStore, recoveryCodeStore, nil, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, audit, log,
		"raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent", 5, time.Minute, noAnomalyThresholds, noStuffingThresholds)

	var secondFactor *ErrSecondFactorRequired
	if !errors.As(err, &secondFactor) {
		t.Fatalf("expected *ErrSecondFactorRequired, got %v", err)
	}
	hasTOTP, hasRecovery := false, false
	for _, m := range secondFactor.Methods {
		if m == "totp" {
			hasTOTP = true
		}
		if m == "recovery_code" {
			hasRecovery = true
		}
	}
	if !hasTOTP || !hasRecovery {
		t.Errorf("expected Methods to contain both totp and recovery_code, got %v", secondFactor.Methods)
	}
}
