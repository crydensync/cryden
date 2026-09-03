package auth

import (
	"context"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/pquerna/otp/totp"
)

func newMFATestDeps(t *testing.T) (*memory.UserStore, *memory.TOTPStore, *memory.AuditStore, security.Hasher, security.TOTPGenerator, security.Encryptor) {
	t.Helper()
	users := memory.NewUserStore()
	totpStore := memory.NewTOTPStore()
	audit := memory.NewAuditStore()
	hasher, _ := security.NewBcryptHasher(4)
	totpGen := security.NewPquernaTOTPGenerator()
	enc, _ := security.NewAESGCMEncryptor("test-encryption-key")
	return users, totpStore, audit, hasher, totpGen, enc
}

func TestEnrollTOTP_ReturnsURLAndStoresUnconfirmedSecret(t *testing.T) {
	users, totpStore, _, hasher, totpGen, enc := newMFATestDeps(t)
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))

	url, err := EnrollTOTP(ctx, users, totpStore, totpGen, enc, "CrydenSync", "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url == "" {
		t.Error("expected a non-empty otpauth:// URL")
	}

	secretRec, err := totpStore.GetByUserID(ctx, "user-1")
	if err != nil {
		t.Fatalf("expected a stored secret record: %v", err)
	}
	if secretRec.ConfirmedAt != nil {
		t.Error("expected a freshly enrolled secret to be unconfirmed")
	}
	if secretRec.EncryptedSecret == "" {
		t.Error("expected the stored secret to be non-empty")
	}
}

func TestEnrollTOTP_RejectsReenrollmentWhenAlreadyConfirmed(t *testing.T) {
	users, totpStore, audit, hasher, totpGen, enc := newMFATestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))

	if _, err := EnrollTOTP(ctx, users, totpStore, totpGen, enc, "CrydenSync", "user-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	code := realCodeFromURL(t, totpGen, enc, totpStore, ctx, "user-1")
	if err := ConfirmTOTP(ctx, totpStore, totpGen, enc, audit, log, "user-1", code); err != nil {
		t.Fatalf("unexpected error confirming: %v", err)
	}

	if _, err := EnrollTOTP(ctx, users, totpStore, totpGen, enc, "CrydenSync", "user-1"); err != ErrTOTPAlreadyEnabled {
		t.Errorf("expected ErrTOTPAlreadyEnabled, got %v", err)
	}
}

func TestConfirmTOTP_RejectsWrongCode(t *testing.T) {
	users, totpStore, audit, hasher, totpGen, enc := newMFATestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	EnrollTOTP(ctx, users, totpStore, totpGen, enc, "CrydenSync", "user-1")

	if err := ConfirmTOTP(ctx, totpStore, totpGen, enc, audit, log, "user-1", "000000"); err != ErrInvalidTOTPCode {
		t.Errorf("expected ErrInvalidTOTPCode, got %v", err)
	}

	// A rejected confirmation must leave the secret unconfirmed —
	// login must still work without a second factor.
	secretRec, _ := totpStore.GetByUserID(ctx, "user-1")
	if secretRec.ConfirmedAt != nil {
		t.Error("expected secret to remain unconfirmed after a failed confirmation attempt")
	}
}

func TestConfirmTOTP_AcceptsCorrectCode(t *testing.T) {
	users, totpStore, audit, hasher, totpGen, enc := newMFATestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	EnrollTOTP(ctx, users, totpStore, totpGen, enc, "CrydenSync", "user-1")

	code := realCodeFromURL(t, totpGen, enc, totpStore, ctx, "user-1")
	if err := ConfirmTOTP(ctx, totpStore, totpGen, enc, audit, log, "user-1", code); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	secretRec, _ := totpStore.GetByUserID(ctx, "user-1")
	if secretRec.ConfirmedAt == nil {
		t.Error("expected secret to be confirmed after a correct code")
	}
}

func TestDisableTOTP_RequiresCorrectPassword(t *testing.T) {
	users, totpStore, audit, hasher, totpGen, enc := newMFATestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	EnrollTOTP(ctx, users, totpStore, totpGen, enc, "CrydenSync", "user-1")
	code := realCodeFromURL(t, totpGen, enc, totpStore, ctx, "user-1")
	ConfirmTOTP(ctx, totpStore, totpGen, enc, audit, log, "user-1", code)

	if err := DisableTOTP(ctx, users, totpStore, hasher, audit, log, "user-1", "wrong-password"); err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials for wrong password, got %v", err)
	}
	if _, err := totpStore.GetByUserID(ctx, "user-1"); err != nil {
		t.Error("expected secret to remain after a rejected disable attempt")
	}

	if err := DisableTOTP(ctx, users, totpStore, hasher, audit, log, "user-1", "Tr0ubl3-Fr33!2026"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := totpStore.GetByUserID(ctx, "user-1"); err != store.ErrNotFound {
		t.Error("expected secret to be deleted after a successful disable")
	}
}

// realCodeFromURL decrypts the stored secret and generates a real,
// currently valid code for it — test-only helper standing in for what
// a real authenticator app would produce during enrollment.
func realCodeFromURL(t *testing.T, totpGen security.TOTPGenerator, enc security.Encryptor, totpStore *memory.TOTPStore, ctx context.Context, userID string) string {
	t.Helper()
	secretRec, err := totpStore.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("failed to fetch secret: %v", err)
	}
	plainSecret, err := enc.Decrypt(secretRec.EncryptedSecret)
	if err != nil {
		t.Fatalf("failed to decrypt secret: %v", err)
	}
	code, err := totp.GenerateCode(plainSecret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate real code: %v", err)
	}
	return code
}
