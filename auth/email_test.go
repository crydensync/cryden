package auth

import (
	"context"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"
)

type captureSender struct {
	to       string
	rawToken string
}

func (c *captureSender) SendVerification(ctx context.Context, to string, rawToken string) error {
	c.to = to
	c.rawToken = rawToken
	return nil
}

func TestRequestEmailChange_DoesNotChangeEmailImmediately(t *testing.T) {
	users := memory.NewUserStore()
	verifications := memory.NewVerificationStore()
	audit := memory.NewAuditStore()
	ids := security.NewUUIDv7Generator()
	tokenGen, _ := token.NewCryptoRandTokenGenerator(32)
	sender := &captureSender{}
	log := testLogger{}
	ctx := context.Background()

	users.Create(ctx, storeUser("user-1", "old@example.com", "hash"))

	err := RequestEmailChange(ctx, users, verifications, sender, tokenGen, ids, audit, log, "user-1", "new@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The critical guarantee: email must NOT change until confirmed.
	user, _ := users.GetByID(ctx, "user-1")
	if user.Email != "old@example.com" {
		t.Errorf("expected email to remain unchanged before confirmation, got %s", user.Email)
	}
	if sender.to != "new@example.com" {
		t.Errorf("expected verification sent to new@example.com, got %s", sender.to)
	}
}

func TestConfirmEmailChange_Success(t *testing.T) {
	users := memory.NewUserStore()
	verifications := memory.NewVerificationStore()
	audit := memory.NewAuditStore()
	ids := security.NewUUIDv7Generator()
	tokenGen, _ := token.NewCryptoRandTokenGenerator(32)
	sender := &captureSender{}
	log := testLogger{}
	ctx := context.Background()

	users.Create(ctx, storeUser("user-1", "old@example.com", "hash"))
	RequestEmailChange(ctx, users, verifications, sender, tokenGen, ids, audit, log, "user-1", "new@example.com")

	err := ConfirmEmailChange(ctx, users, verifications, audit, log, sender.rawToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	user, _ := users.GetByID(ctx, "user-1")
	if user.Email != "new@example.com" {
		t.Errorf("expected email updated to new@example.com, got %s", user.Email)
	}
}

func TestConfirmEmailChange_RejectsTokenReuse(t *testing.T) {
	users := memory.NewUserStore()
	verifications := memory.NewVerificationStore()
	audit := memory.NewAuditStore()
	ids := security.NewUUIDv7Generator()
	tokenGen, _ := token.NewCryptoRandTokenGenerator(32)
	sender := &captureSender{}
	log := testLogger{}
	ctx := context.Background()

	users.Create(ctx, storeUser("user-1", "old@example.com", "hash"))
	RequestEmailChange(ctx, users, verifications, sender, tokenGen, ids, audit, log, "user-1", "new@example.com")

	if err := ConfirmEmailChange(ctx, users, verifications, audit, log, sender.rawToken); err != nil {
		t.Fatalf("expected first confirmation to succeed: %v", err)
	}

	// Reusing the same token a second time must fail — it's single-use.
	err := ConfirmEmailChange(ctx, users, verifications, audit, log, sender.rawToken)
	if err != ErrVerificationTokenInvalid {
		t.Errorf("expected ErrVerificationTokenInvalid on reuse, got %v", err)
	}
}

func TestConfirmEmailChange_RejectsUnknownToken(t *testing.T) {
	users := memory.NewUserStore()
	verifications := memory.NewVerificationStore()
	audit := memory.NewAuditStore()
	log := testLogger{}
	ctx := context.Background()

	err := ConfirmEmailChange(ctx, users, verifications, audit, log, "never-issued-token")
	if err != ErrVerificationTokenInvalid {
		t.Errorf("expected ErrVerificationTokenInvalid, got %v", err)
	}
}

func TestConfirmEmailChange_RejectsExpiredToken(t *testing.T) {
	users := memory.NewUserStore()
	verifications := memory.NewVerificationStore()
	audit := memory.NewAuditStore()
	ids := security.NewUUIDv7Generator()
	log := testLogger{}
	ctx := context.Background()

	users.Create(ctx, storeUser("user-1", "old@example.com", "hash"))

	// Construct an already-expired token directly — bypasses
	// RequestEmailChange's real TTL so the test doesn't need to sleep
	// past a full hour.
	rawToken := "expired-test-token"
	id, _ := ids.New()
	verifications.Create(ctx, store.VerificationToken{
		ID:        id,
		UserID:    "user-1",
		Purpose:   store.PurposeEmailChange,
		TokenHash: token.HashToken(rawToken),
		NewEmail:  "new@example.com",
		ExpiresAt: time.Now().Add(-1 * time.Minute), // already expired
	})

	err := ConfirmEmailChange(ctx, users, verifications, audit, log, rawToken)
	if err != ErrVerificationTokenExpired {
		t.Errorf("expected ErrVerificationTokenExpired, got %v", err)
	}

	// Email must remain unchanged — an expired token must not apply
	// the change even partially.
	user, _ := users.GetByID(ctx, "user-1")
	if user.Email != "old@example.com" {
		t.Errorf("expected email unchanged after expired-token attempt, got %s", user.Email)
	}
}

func TestRequestEmailChange_RejectsAlreadyTakenEmail(t *testing.T) {
	users := memory.NewUserStore()
	verifications := memory.NewVerificationStore()
	audit := memory.NewAuditStore()
	ids := security.NewUUIDv7Generator()
	tokenGen, _ := token.NewCryptoRandTokenGenerator(32)
	sender := &captureSender{}
	log := testLogger{}
	ctx := context.Background()

	users.Create(ctx, storeUser("user-1", "proguy@example.com", "hash"))
	users.Create(ctx, storeUser("user-2", "bob@example.com", "hash"))

	err := RequestEmailChange(ctx, users, verifications, sender, tokenGen, ids, audit, log, "user-1", "bob@example.com")
	if err != ErrUserExists {
		t.Errorf("expected ErrUserExists, got %v", err)
	}
}
