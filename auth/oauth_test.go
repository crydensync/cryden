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

func newOAuthTestDeps(t *testing.T) (*memory.UserStore, *memory.OAuthStore, *memory.SessionStore, *memory.AuditStore, security.IDGenerator, token.TokenGenerator, *token.JWTIssuer) {
	t.Helper()
	users := memory.NewUserStore()
	oauth := memory.NewOAuthStore()
	sessions := memory.NewSessionStore()
	audit := memory.NewAuditStore()
	ids := security.NewUUIDv7Generator()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	return users, oauth, sessions, audit, ids, refreshGen, jwtIssuer
}

func TestLoginWithOAuth_NewIdentityCreatesUserAndSession(t *testing.T) {
	users, oauth, sessions, audit, ids, refreshGen, jwtIssuer := newOAuthTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	tokens, err := LoginWithOAuth(ctx, users, oauth, sessions, ids, refreshGen, jwtIssuer, audit, log,
		"google", "google-ext-id-1", "proguy@example.com", "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Error("expected both tokens to be populated")
	}

	user, err := users.GetByEmail(ctx, "proguy@example.com")
	if err != nil {
		t.Fatalf("expected a new user to be created: %v", err)
	}

	identity, err := oauth.GetByProviderID(ctx, "google", "google-ext-id-1")
	if err != nil {
		t.Fatalf("expected an oauth identity to be linked: %v", err)
	}
	if identity.UserID != user.ID {
		t.Errorf("expected identity.UserID %q to match new user %q", identity.UserID, user.ID)
	}
}

func TestLoginWithOAuth_ExistingLinkIssuesSession(t *testing.T) {
	users, oauth, sessions, audit, ids, refreshGen, jwtIssuer := newOAuthTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	users.Create(ctx, storeUser("user-1", "devray@example.com", ""))
	oauth.Link(ctx, store.OAuthIdentity{
		ID: "identity-1", UserID: "user-1", Provider: "github", ExternalID: "gh-ext-id-1", Email: "devray@example.com",
	})

	tokens, err := LoginWithOAuth(ctx, users, oauth, sessions, ids, refreshGen, jwtIssuer, audit, log,
		"github", "gh-ext-id-1", "devray@example.com", "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Error("expected both tokens to be populated")
	}

	// No second identity or duplicate user should have been created.
	all, _ := oauth.ListByUser(ctx, "user-1")
	if len(all) != 1 {
		t.Errorf("expected exactly 1 linked identity, got %d", len(all))
	}
}

func TestLoginWithOAuth_EmailConflictWithPasswordAccountIsRejected(t *testing.T) {
	// The core account-linking decision: an OAuth login must NOT
	// auto-link to an existing password-based account on email
	// match alone — that's an account-takeover vector. It must
	// return *ErrOAuthEmailConflict instead, retrievable via
	// errors.As, and must not create a session or a new identity.
	users, oauth, sessions, audit, ids, refreshGen, jwtIssuer := newOAuthTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	users.Create(ctx, storeUser("user-1", "proguy@example.com", "some-password-hash"))

	_, err := LoginWithOAuth(ctx, users, oauth, sessions, ids, refreshGen, jwtIssuer, audit, log,
		"google", "google-ext-id-2", "proguy@example.com", "1.2.3.4", "test-agent")

	var conflict *ErrOAuthEmailConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("expected *ErrOAuthEmailConflict, got %v", err)
	}
	if conflict.Email != "proguy@example.com" || conflict.Provider != "google" {
		t.Errorf("unexpected conflict fields: %+v", conflict)
	}

	if _, getErr := oauth.GetByProviderID(ctx, "google", "google-ext-id-2"); getErr != store.ErrNotFound {
		t.Error("no oauth identity should have been created on conflict")
	}
}

func TestLinkOAuthIdentity_NewLinkSucceeds(t *testing.T) {
	users, oauth, _, audit, ids, _, _ := newOAuthTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	users.Create(ctx, storeUser("user-1", "proguy@example.com", "some-password-hash"))

	err := LinkOAuthIdentity(ctx, users, oauth, ids, audit, log, "user-1", "google", "google-ext-id-1", "proguy@example.com", "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	identity, err := oauth.GetByProviderID(ctx, "google", "google-ext-id-1")
	if err != nil {
		t.Fatalf("expected identity to be linked: %v", err)
	}
	if identity.UserID != "user-1" {
		t.Errorf("expected identity linked to user-1, got %q", identity.UserID)
	}
}

func TestLinkOAuthIdentity_AlreadyLinkedToSameUserIsIdempotent(t *testing.T) {
	users, oauth, _, audit, ids, _, _ := newOAuthTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	users.Create(ctx, storeUser("user-1", "proguy@example.com", "some-password-hash"))
	oauth.Link(ctx, store.OAuthIdentity{
		ID: "identity-1", UserID: "user-1", Provider: "google", ExternalID: "google-ext-id-1", Email: "proguy@example.com",
	})

	err := LinkOAuthIdentity(ctx, users, oauth, ids, audit, log, "user-1", "google", "google-ext-id-1", "proguy@example.com", "1.2.3.4")
	if err != nil {
		t.Errorf("expected no error re-linking the same user to the same identity, got %v", err)
	}
}

func TestLinkOAuthIdentity_ClaimedByDifferentUserIsRejected(t *testing.T) {
	// The other half of the account-takeover protection: even an
	// authenticated user must not be able to steal a provider
	// identity that's already linked to someone else's account.
	users, oauth, _, audit, ids, _, _ := newOAuthTestDeps(t)
	log := testLogger{}
	ctx := context.Background()

	users.Create(ctx, storeUser("user-1", "victim@example.com", "hash-1"))
	users.Create(ctx, storeUser("user-2", "attacker@example.com", "hash-2"))
	oauth.Link(ctx, store.OAuthIdentity{
		ID: "identity-1", UserID: "user-1", Provider: "google", ExternalID: "google-ext-id-1", Email: "victim@example.com",
	})

	err := LinkOAuthIdentity(ctx, users, oauth, ids, audit, log, "user-2", "google", "google-ext-id-1", "attacker@example.com", "1.2.3.4")
	if err != ErrOAuthIdentityAlreadyLinked {
		t.Errorf("expected ErrOAuthIdentityAlreadyLinked, got %v", err)
	}

	identity, _ := oauth.GetByProviderID(ctx, "google", "google-ext-id-1")
	if identity.UserID != "user-1" {
		t.Errorf("identity must remain linked to original owner user-1, got %q", identity.UserID)
	}
}
