package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

func TestOAuthStore_LinkAndLookup(t *testing.T) {
	db := newTestDB(t)
	oauth := NewOAuthStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if err := oauth.Link(ctx, store.OAuthIdentity{
		ID: "oi-1", UserID: "user-1", Provider: "google",
		ExternalID: "ext-1", Email: "raymondproguy@dev.com",
	}); err != nil {
		t.Fatalf("Link: %v", err)
	}

	oi, err := oauth.GetByProviderID(ctx, "google", "ext-1")
	if err != nil {
		t.Fatalf("GetByProviderID: %v", err)
	}
	if oi.UserID != "user-1" || oi.Email != "raymondproguy@dev.com" {
		t.Errorf("wrong row back: %+v", oi)
	}
	if oi.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero; the store must assign it")
	}

	// Provider is half the key: the same external ID at a different
	// provider is a different account entirely.
	if _, err := oauth.GetByProviderID(ctx, "github", "ext-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("same external ID at another provider: got %v, want store.ErrNotFound", err)
	}
	if _, err := oauth.GetByProviderID(ctx, "google", "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetByProviderID missing: got %v, want store.ErrNotFound", err)
	}
}

// The UNIQUE (provider, external_id) constraint is the real guard
// against one external account being claimed by two local users — an
// account-takeover primitive if it ever stopped holding.
func TestOAuthStore_SameExternalAccountCannotBeLinkedTwice(t *testing.T) {
	db := newTestDB(t)
	oauth := NewOAuthStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")
	seedUser(t, db, "user-2", "attacker@dev.com")

	if err := oauth.Link(ctx, store.OAuthIdentity{
		ID: "oi-1", UserID: "user-1", Provider: "google", ExternalID: "ext-1", Email: "raymondproguy@dev.com",
	}); err != nil {
		t.Fatalf("first Link: %v", err)
	}
	err := oauth.Link(ctx, store.OAuthIdentity{
		ID: "oi-2", UserID: "user-2", Provider: "google", ExternalID: "ext-1", Email: "attacker@dev.com",
	})
	if err == nil {
		t.Fatal("the same external account was linked to a second user")
	}
}

func TestOAuthStore_ListByUserAndUnlink(t *testing.T) {
	db := newTestDB(t)
	oauth := NewOAuthStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")
	seedUser(t, db, "user-2", "other@dev.com")

	for i, provider := range []string{"google", "github", "gitlab"} {
		if err := oauth.Link(ctx, store.OAuthIdentity{
			ID: "oi-" + provider, UserID: "user-1", Provider: provider,
			ExternalID: "ext-1", Email: "raymondproguy@dev.com",
		}); err != nil {
			t.Fatalf("Link %d: %v", i, err)
		}
		time.Sleep(time.Millisecond)
	}
	if err := oauth.Link(ctx, store.OAuthIdentity{
		ID: "oi-other", UserID: "user-2", Provider: "google", ExternalID: "ext-2", Email: "other@dev.com",
	}); err != nil {
		t.Fatalf("Link for user-2: %v", err)
	}

	list, err := oauth.ListByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("got %d identities, want 3", len(list))
	}
	// Newest first, matching Postgres.
	if list[0].Provider != "gitlab" {
		t.Errorf("first identity is %q, want gitlab", list[0].Provider)
	}
	for _, oi := range list {
		if oi.UserID != "user-1" {
			t.Errorf("another user's identity leaked in: %+v", oi)
		}
	}

	if err := oauth.Unlink(ctx, "oi-github"); err != nil {
		t.Fatalf("Unlink: %v", err)
	}
	if list, err = oauth.ListByUser(ctx, "user-1"); err != nil || len(list) != 2 {
		t.Errorf("after Unlink: %d identities, %v; want 2", len(list), err)
	}
	if err := oauth.Unlink(ctx, "oi-github"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second Unlink: got %v, want store.ErrNotFound", err)
	}

	if empty, err := oauth.ListByUser(ctx, "nobody"); err != nil || len(empty) != 0 {
		t.Errorf("ListByUser for an unknown user: %d rows, %v", len(empty), err)
	}
}
