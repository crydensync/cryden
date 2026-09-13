package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"
)

func TestLogin_WebAuthnOnlyReportsWebAuthnMethod(t *testing.T) {
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	webauthnStore := memory.NewWebAuthnStore()
	audit := memory.NewAuditStore()
	hasher, _ := security.NewBcryptHasher(4)
	ids := security.NewUUIDv7Generator()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")
	limiter := security.NewInMemoryRateLimiter(1000, time.Minute)
	provider, _ := security.NewGoWebAuthnProvider(testWebAuthnRPDisplayName, testWebAuthnRPID, []string{testWebAuthnRPOrigin})
	enc, _ := security.NewAESGCMEncryptor("test-encryption-key")
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	registerRealPasskeyForUser(t, ctx, users, webauthnStore, provider, enc, ids, audit, "user-1")

	_, err := Login(ctx, users, sessions, nil, webauthnStore, nil, nil, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, audit, log,
		"raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent", 5, time.Minute, noAnomalyThresholds)

	var secondFactor *ErrSecondFactorRequired
	if !errors.As(err, &secondFactor) {
		t.Fatalf("expected *ErrSecondFactorRequired, got %v", err)
	}
	if len(secondFactor.Methods) != 1 || secondFactor.Methods[0] != "webauthn" {
		t.Errorf("expected Methods to be exactly [\"webauthn\"], got %v", secondFactor.Methods)
	}
}

func TestLogin_TOTPAndWebAuthnBothReportBothMethods(t *testing.T) {
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	totpStore := memory.NewTOTPStore()
	webauthnStore := memory.NewWebAuthnStore()
	audit := memory.NewAuditStore()
	hasher, _ := security.NewBcryptHasher(4)
	ids := security.NewUUIDv7Generator()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")
	limiter := security.NewInMemoryRateLimiter(1000, time.Minute)
	provider, _ := security.NewGoWebAuthnProvider(testWebAuthnRPDisplayName, testWebAuthnRPID, []string{testWebAuthnRPOrigin})
	totpGen := security.NewPquernaTOTPGenerator()
	enc, _ := security.NewAESGCMEncryptor("test-encryption-key")
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	enrollAndConfirm(t, ctx, users, totpStore, audit, totpGen, enc, "user-1")
	registerRealPasskeyForUser(t, ctx, users, webauthnStore, provider, enc, ids, audit, "user-1")

	_, err := Login(ctx, users, sessions, totpStore, webauthnStore, nil, nil, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, audit, log,
		"raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent", 5, time.Minute, noAnomalyThresholds)

	var secondFactor *ErrSecondFactorRequired
	if !errors.As(err, &secondFactor) {
		t.Fatalf("expected *ErrSecondFactorRequired, got %v", err)
	}
	if len(secondFactor.Methods) != 2 {
		t.Fatalf("expected both methods reported, got %v", secondFactor.Methods)
	}
	hasTOTP, hasWebAuthn := false, false
	for _, m := range secondFactor.Methods {
		if m == "totp" {
			hasTOTP = true
		}
		if m == "webauthn" {
			hasWebAuthn = true
		}
	}
	if !hasTOTP || !hasWebAuthn {
		t.Errorf("expected Methods to contain both totp and webauthn, got %v", secondFactor.Methods)
	}
}

func TestLogin_NoSecondFactorEnrolledIssuesTokensDirectly(t *testing.T) {
	// Sanity check: with both stores configured but nothing enrolled,
	// login must behave exactly as if neither feature existed.
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	totpStore := memory.NewTOTPStore()
	webauthnStore := memory.NewWebAuthnStore()
	audit := memory.NewAuditStore()
	hasher, _ := security.NewBcryptHasher(4)
	ids := security.NewUUIDv7Generator()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")
	limiter := security.NewInMemoryRateLimiter(1000, time.Minute)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))

	tokens, err := Login(ctx, users, sessions, totpStore, webauthnStore, nil, nil, hasher, ids, refreshGen, jwtIssuer, pendingIssuer, limiter, audit, log,
		"raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent", 5, time.Minute, noAnomalyThresholds)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Error("expected tokens to be issued directly")
	}
}
