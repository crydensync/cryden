package auth

import (
	"context"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"
)

const (
	testWebAuthnRPDisplayName = "CrydenSync Test"
	testWebAuthnRPID          = "example.com"
	testWebAuthnRPOrigin      = "https://example.com"
)

func newWebAuthnTestDeps(t *testing.T) (*memory.UserStore, *memory.WebAuthnStore, *memory.AuditStore, security.Hasher, security.IDGenerator, *security.GoWebAuthnProvider, security.Encryptor) {
	t.Helper()
	users := memory.NewUserStore()
	webauthnStore := memory.NewWebAuthnStore()
	audit := memory.NewAuditStore()
	hasher, _ := security.NewBcryptHasher(4)
	ids := security.NewUUIDv7Generator()
	provider, err := security.NewGoWebAuthnProvider(testWebAuthnRPDisplayName, testWebAuthnRPID, []string{testWebAuthnRPOrigin})
	if err != nil {
		t.Fatalf("failed to construct provider: %v", err)
	}
	enc, _ := security.NewAESGCMEncryptor("test-encryption-key")
	return users, webauthnStore, audit, hasher, ids, provider, enc
}

// registerRealPasskeyForUser drives the full BeginRegisterPasskey /
// FinishRegisterPasskey round trip through a real simulated
// authenticator, exactly as a browser would, and returns the
// authenticator/credential so a later test can also complete a login
// with the same passkey.
func registerRealPasskeyForUser(
	t *testing.T,
	ctx context.Context,
	users *memory.UserStore,
	webauthnStore *memory.WebAuthnStore,
	provider *security.GoWebAuthnProvider,
	enc security.Encryptor,
	ids security.IDGenerator,
	audit *memory.AuditStore,
	userID string,
) (virtualwebauthn.Authenticator, virtualwebauthn.Credential) {
	t.Helper()
	log := testLogger{}
	rp := virtualwebauthn.RelyingParty{Name: testWebAuthnRPDisplayName, ID: testWebAuthnRPID, Origin: testWebAuthnRPOrigin}
	authenticator := virtualwebauthn.NewAuthenticator()
	vCred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	creationJSON, ceremonyToken, err := BeginRegisterPasskey(ctx, users, webauthnStore, provider, enc, userID)
	if err != nil {
		t.Fatalf("BeginRegisterPasskey failed: %v", err)
	}

	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(creationJSON))
	if err != nil {
		t.Fatalf("ParseAttestationOptions failed: %v", err)
	}
	responseJSON := virtualwebauthn.CreateAttestationResponse(rp, authenticator, vCred, *attestationOptions)

	if err := FinishRegisterPasskey(ctx, users, webauthnStore, provider, enc, ids, audit, log, userID, ceremonyToken, []byte(responseJSON), "Test Device"); err != nil {
		t.Fatalf("FinishRegisterPasskey failed: %v", err)
	}

	authenticator.AddCredential(vCred)
	authenticator.Options.UserHandle = []byte(userID)
	return authenticator, vCred
}

func TestBeginFinishRegisterPasskey_StoresACredential(t *testing.T) {
	users, webauthnStore, audit, hasher, ids, provider, enc := newWebAuthnTestDeps(t)
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))

	registerRealPasskeyForUser(t, ctx, users, webauthnStore, provider, enc, ids, audit, "user-1")

	creds, err := ListPasskeys(ctx, webauthnStore, "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 registered passkey, got %d", len(creds))
	}
	if creds[0].Nickname != "Test Device" {
		t.Errorf("expected nickname 'Test Device', got %q", creds[0].Nickname)
	}
}

func TestFinishRegisterPasskey_RejectsGarbageResponse(t *testing.T) {
	users, webauthnStore, audit, hasher, ids, provider, enc := newWebAuthnTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))

	_, ceremonyToken, err := BeginRegisterPasskey(ctx, users, webauthnStore, provider, enc, "user-1")
	if err != nil {
		t.Fatalf("BeginRegisterPasskey failed: %v", err)
	}

	err = FinishRegisterPasskey(ctx, users, webauthnStore, provider, enc, ids, audit, log, "user-1", ceremonyToken, []byte(`{"not":"real"}`), "")
	if err != ErrInvalidWebAuthnResponse {
		t.Errorf("expected ErrInvalidWebAuthnResponse, got %v", err)
	}
}

func TestFinishRegisterPasskey_RejectsTamperedCeremonyToken(t *testing.T) {
	users, webauthnStore, audit, hasher, ids, provider, enc := newWebAuthnTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))

	err := FinishRegisterPasskey(ctx, users, webauthnStore, provider, enc, ids, audit, log, "user-1", "not-a-real-ceremony-token", []byte(`{}`), "")
	if err != ErrInvalidCeremonyToken {
		t.Errorf("expected ErrInvalidCeremonyToken, got %v", err)
	}
}

func TestDeletePasskey_RequiresCorrectPassword(t *testing.T) {
	users, webauthnStore, audit, hasher, ids, provider, enc := newWebAuthnTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	_, vCred := registerRealPasskeyForUser(t, ctx, users, webauthnStore, provider, enc, ids, audit, "user-1")

	if err := DeletePasskey(ctx, users, webauthnStore, hasher, audit, log, "user-1", vCred.ID, "wrong-password"); err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
	creds, _ := ListPasskeys(ctx, webauthnStore, "user-1")
	if len(creds) != 1 {
		t.Error("expected the passkey to remain after a rejected delete attempt")
	}

	if err := DeletePasskey(ctx, users, webauthnStore, hasher, audit, log, "user-1", vCred.ID, "Tr0ubl3-Fr33!2026"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	creds, _ = ListPasskeys(ctx, webauthnStore, "user-1")
	if len(creds) != 0 {
		t.Error("expected the passkey to be removed after a successful delete")
	}
}

func TestBeginCompleteWebAuthnLogin_CorrectResponseIssuesTokens(t *testing.T) {
	users, webauthnStore, audit, hasher, ids, provider, enc := newWebAuthnTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	authenticator, vCred := registerRealPasskeyForUser(t, ctx, users, webauthnStore, provider, enc, ids, audit, "user-1")

	sessions := memory.NewSessionStore()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")

	pendingToken, err := pendingIssuer.Issue("user-1")
	if err != nil {
		t.Fatalf("failed to issue a test pending token: %v", err)
	}

	assertionJSON, ceremonyToken, err := BeginWebAuthnLogin(ctx, users, webauthnStore, provider, enc, pendingIssuer, pendingToken)
	if err != nil {
		t.Fatalf("BeginWebAuthnLogin failed: %v", err)
	}

	rp := virtualwebauthn.RelyingParty{Name: testWebAuthnRPDisplayName, ID: testWebAuthnRPID, Origin: testWebAuthnRPOrigin}
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(assertionJSON))
	if err != nil {
		t.Fatalf("ParseAssertionOptions failed: %v", err)
	}
	responseJSON := virtualwebauthn.CreateAssertionResponse(rp, authenticator, vCred, *assertionOptions)

	tokens, err := CompleteLoginWithWebAuthn(ctx, users, sessions, webauthnStore, provider, enc, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log,
		pendingToken, ceremonyToken, []byte(responseJSON), "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Error("expected both tokens to be populated")
	}
}

func TestCompleteWebAuthnLogin_RejectsGarbageResponse(t *testing.T) {
	users, webauthnStore, audit, hasher, ids, provider, enc := newWebAuthnTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))
	registerRealPasskeyForUser(t, ctx, users, webauthnStore, provider, enc, ids, audit, "user-1")

	sessions := memory.NewSessionStore()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")
	pendingToken, _ := pendingIssuer.Issue("user-1")

	_, ceremonyToken, err := BeginWebAuthnLogin(ctx, users, webauthnStore, provider, enc, pendingIssuer, pendingToken)
	if err != nil {
		t.Fatalf("BeginWebAuthnLogin failed: %v", err)
	}

	_, err = CompleteLoginWithWebAuthn(ctx, users, sessions, webauthnStore, provider, enc, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log,
		pendingToken, ceremonyToken, []byte(`{"not":"real"}`), "1.2.3.4", "test-agent")
	if err != ErrInvalidWebAuthnResponse {
		t.Errorf("expected ErrInvalidWebAuthnResponse, got %v", err)
	}
}

func TestBeginWebAuthnLogin_RejectsAccountWithNoPasskeys(t *testing.T) {
	users, webauthnStore, _, hasher, _, provider, enc := newWebAuthnTestDeps(t)
	ctx := context.Background()

	hash, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", hash))

	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")
	pendingToken, _ := pendingIssuer.Issue("user-1")

	_, _, err := BeginWebAuthnLogin(ctx, users, webauthnStore, provider, enc, pendingIssuer, pendingToken)
	if err != ErrNoPasskeysEnrolled {
		t.Errorf("expected ErrNoPasskeysEnrolled, got %v", err)
	}
}
