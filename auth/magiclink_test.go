package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"
)

type captureMagicLinkSender struct {
	to       string
	rawToken string
	calls    int
}

func (c *captureMagicLinkSender) SendMagicLink(ctx context.Context, to string, rawToken string) error {
	c.to = to
	c.rawToken = rawToken
	c.calls++
	return nil
}

func newMagicLinkTestDeps(t *testing.T) (*memory.UserStore, *memory.VerificationStore, *memory.AuditStore, security.IDGenerator, token.TokenGenerator, *captureMagicLinkSender, security.RateLimiter) {
	t.Helper()
	users := memory.NewUserStore()
	verifications := memory.NewVerificationStore()
	audit := memory.NewAuditStore()
	ids := security.NewUUIDv7Generator()
	tokenGen, _ := token.NewCryptoRandTokenGenerator(32)
	sender := &captureMagicLinkSender{}
	limiter := security.NewInMemoryRateLimiter(1000, time.Minute)
	return users, verifications, audit, ids, tokenGen, sender, limiter
}

func TestRequestMagicLink_SendsForExistingAccount(t *testing.T) {
	users, verifications, audit, ids, tokenGen, sender, limiter := newMagicLinkTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", "hash"))

	err := RequestMagicLink(ctx, users, verifications, sender, tokenGen, ids, limiter, audit, log, "raymondproguy@dev.com", "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sender.calls != 1 {
		t.Fatalf("expected exactly 1 send, got %d", sender.calls)
	}
	if sender.to != "raymondproguy@dev.com" {
		t.Errorf("expected send to raymondproguy@dev.com, got %q", sender.to)
	}
	if sender.rawToken == "" {
		t.Error("expected a non-empty token")
	}
}

func TestRequestMagicLink_NonexistentEmailReturnsNilWithoutSending(t *testing.T) {
	// Enumeration-avoidance: must return the same nil as a real
	// account, and must never call the sender for an address with no
	// account behind it.
	users, verifications, audit, ids, tokenGen, sender, limiter := newMagicLinkTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	err := RequestMagicLink(ctx, users, verifications, sender, tokenGen, ids, limiter, audit, log, "nobody@example.com", "1.2.3.4")
	if err != nil {
		t.Errorf("expected nil error for a nonexistent email, got %v", err)
	}
	if sender.calls != 0 {
		t.Errorf("expected the sender to never be called for a nonexistent email, got %d calls", sender.calls)
	}
}

func TestCompleteMagicLink_ValidTokenIssuesTokens(t *testing.T) {
	users, verifications, audit, ids, tokenGen, sender, limiter := newMagicLinkTestDeps(t)
	log := testLogger{}
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")

	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", "hash"))
	if err := RequestMagicLink(ctx, users, verifications, sender, tokenGen, ids, limiter, audit, log, "raymondproguy@dev.com", "1.2.3.4"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tokens, err := CompleteMagicLink(ctx, users, sessions, verifications, nil, nil, nil, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log, sender.rawToken, "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Error("expected both tokens to be populated")
	}
}

func TestCompleteMagicLink_TokenIsSingleUse(t *testing.T) {
	users, verifications, audit, ids, tokenGen, sender, limiter := newMagicLinkTestDeps(t)
	log := testLogger{}
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")

	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", "hash"))
	RequestMagicLink(ctx, users, verifications, sender, tokenGen, ids, limiter, audit, log, "raymondproguy@dev.com", "1.2.3.4")

	if _, err := CompleteMagicLink(ctx, users, sessions, verifications, nil, nil, nil, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log, sender.rawToken, "1.2.3.4", "test-agent"); err != nil {
		t.Fatalf("unexpected error on first use: %v", err)
	}

	_, err := CompleteMagicLink(ctx, users, sessions, verifications, nil, nil, nil, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log, sender.rawToken, "1.2.3.4", "test-agent")
	if err != ErrVerificationTokenInvalid {
		t.Errorf("expected ErrVerificationTokenInvalid on reuse, got %v", err)
	}
}

func TestCompleteMagicLink_ExpiredTokenRejected(t *testing.T) {
	users, verifications, audit, ids, _, _, _ := newMagicLinkTestDeps(t)
	log := testLogger{}
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")
	tokenGen, _ := token.NewCryptoRandTokenGenerator(32)

	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", "hash"))

	rawToken, _ := tokenGen.New()
	id, _ := ids.New()
	verifications.Create(ctx, store.VerificationToken{
		ID:        id,
		UserID:    "user-1",
		Purpose:   store.PurposeMagicLink,
		TokenHash: token.HashToken(rawToken),
		ExpiresAt: time.Now().Add(-1 * time.Minute), // already expired
	})

	_, err := CompleteMagicLink(ctx, users, sessions, verifications, nil, nil, nil, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log, rawToken, "1.2.3.4", "test-agent")
	if err != ErrVerificationTokenExpired {
		t.Errorf("expected ErrVerificationTokenExpired, got %v", err)
	}
}

func TestCompleteMagicLink_WrongPurposeTokenRejected(t *testing.T) {
	// A token minted for a different purpose (e.g. email change) must
	// never be usable to log in, even if someone got hold of its raw
	// value — the Purpose check is what enforces that separation.
	users, verifications, audit, ids, _, _, _ := newMagicLinkTestDeps(t)
	log := testLogger{}
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")
	tokenGen, _ := token.NewCryptoRandTokenGenerator(32)

	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", "hash"))

	rawToken, _ := tokenGen.New()
	id, _ := ids.New()
	verifications.Create(ctx, store.VerificationToken{
		ID:        id,
		UserID:    "user-1",
		Purpose:   store.PurposeEmailChange,
		TokenHash: token.HashToken(rawToken),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	_, err := CompleteMagicLink(ctx, users, sessions, verifications, nil, nil, nil, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log, rawToken, "1.2.3.4", "test-agent")
	if err != ErrVerificationTokenInvalid {
		t.Errorf("expected ErrVerificationTokenInvalid for a wrong-purpose token, got %v", err)
	}
}

func TestCompleteMagicLink_AccountWithTOTPPausesForSecondFactor(t *testing.T) {
	users, verifications, audit, ids, tokenGen, sender, limiter := newMagicLinkTestDeps(t)
	log := testLogger{}
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")
	totpStore := memory.NewTOTPStore()
	totpGen := security.NewPquernaTOTPGenerator()
	enc, _ := security.NewAESGCMEncryptor("test-encryption-key")

	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", "hash"))
	enrollAndConfirm(t, ctx, users, totpStore, audit, totpGen, enc, "user-1")

	RequestMagicLink(ctx, users, verifications, sender, tokenGen, ids, limiter, audit, log, "raymondproguy@dev.com", "1.2.3.4")

	_, err := CompleteMagicLink(ctx, users, sessions, verifications, totpStore, nil, nil, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log, sender.rawToken, "1.2.3.4", "test-agent")

	var secondFactor *ErrSecondFactorRequired
	if !errors.As(err, &secondFactor) {
		t.Fatalf("expected *ErrSecondFactorRequired, got %v", err)
	}
	if len(secondFactor.Methods) != 1 || secondFactor.Methods[0] != "totp" {
		t.Errorf("expected Methods == [\"totp\"], got %v", secondFactor.Methods)
	}
}
