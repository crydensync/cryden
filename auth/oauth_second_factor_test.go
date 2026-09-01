package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"
)

func TestLoginWithOAuth_AccountWithTOTPPausesForSecondFactor(t *testing.T) {
	// Regression test: LoginWithOAuth used to do its own inline
	// session issuance, bypassing the second-factor gate entirely —
	// an account with TOTP/a passkey enrolled would log straight in
	// via a linked OAuth identity with no second-factor check at all.
	users, oauth, sessions, audit, ids, refreshGen, jwtIssuer := newOAuthTestDeps(t)
	totpStore := memory.NewTOTPStore()
	totpGen := security.NewPquernaTOTPGenerator()
	enc, _ := security.NewAESGCMEncryptor("test-encryption-key")
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")
	log := testLogger{}
	ctx := context.Background()

	// First OAuth login creates the account (no second factor exists yet).
	_, err := LoginWithOAuth(ctx, users, oauth, sessions, totpStore, nil, nil, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log,
		"google", "google-ext-id-1", "raymondproguy@dev.com", "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("unexpected error on first login: %v", err)
	}

	identity, err := oauth.GetByProviderID(ctx, "google", "google-ext-id-1")
	if err != nil {
		t.Fatalf("failed to look up the created identity: %v", err)
	}
	enrollAndConfirm(t, ctx, users, totpStore, audit, totpGen, enc, identity.UserID)

	// Second OAuth login for the same identity — now with TOTP
	// enrolled and confirmed — must pause instead of logging straight in.
	tokens, err := LoginWithOAuth(ctx, users, oauth, sessions, totpStore, nil, nil, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log,
		"google", "google-ext-id-1", "raymondproguy@dev.com", "1.2.3.4", "test-agent")

	var secondFactor *ErrSecondFactorRequired
	if !errors.As(err, &secondFactor) {
		t.Fatalf("expected *ErrSecondFactorRequired, got %v", err)
	}
	if tokens.AccessToken != "" {
		t.Error("expected no access token to be issued before the second factor is completed")
	}
	if len(secondFactor.Methods) != 1 || secondFactor.Methods[0] != "totp" {
		t.Errorf("expected Methods == [\"totp\"], got %v", secondFactor.Methods)
	}
}

func TestLoginWithOAuth_AuditRecordsProvider(t *testing.T) {
	// The pre-refactor code tagged the login_success audit event with
	// which provider was used — confirms that detail survived moving
	// session issuance into the shared completePrimaryAuth helper.
	users, oauth, sessions, audit, ids, refreshGen, jwtIssuer := newOAuthTestDeps(t)
	pendingIssuer, _ := token.NewMFAPendingIssuer("test-secret")
	log := testLogger{}
	ctx := context.Background()

	_, err := LoginWithOAuth(ctx, users, oauth, sessions, nil, nil, nil, ids, refreshGen, jwtIssuer, pendingIssuer, audit, log,
		"github", "github-ext-id-1", "raymondproguy@dev.com", "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events, err := audit.SearchByType(ctx, store.EventLoginSuccess, 10)
	if err != nil {
		t.Fatalf("unexpected error searching audit events: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Metadata["provider"] == "github" {
			found = true
		}
	}
	if !found {
		t.Error("expected a login_success audit event tagged with provider=github")
	}
}
