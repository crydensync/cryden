package sqlite

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/crydensync/cryden/v2/store"
)

func TestWebAuthnStore_AddAndList(t *testing.T) {
	db := newTestDB(t)
	passkeys := NewWebAuthnStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	credID := []byte{0x00, 0x01, 0xff, 0xfe}
	credData := []byte(`{"ID":"abc","Authenticator":{"SignCount":1}}`)
	if err := passkeys.Add(ctx, store.WebAuthnCredential{
		ID: "wa-1", UserID: "user-1", CredentialID: credID,
		CredentialData: credData, Nickname: "MacBook Touch ID",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	list, err := passkeys.ListByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d credentials, want 1", len(list))
	}
	got := list[0]
	// Raw bytes through a BLOB column, including the 0x00 that would
	// truncate anything treating them as a C string.
	if !bytes.Equal(got.CredentialID, credID) {
		t.Errorf("CredentialID = %v, want %v", got.CredentialID, credID)
	}
	if !bytes.Equal(got.CredentialData, credData) {
		t.Errorf("CredentialData = %s, want %s", got.CredentialData, credData)
	}
	if got.Nickname != "MacBook Touch ID" {
		t.Errorf("Nickname = %q", got.Nickname)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero; the store must assign it")
	}
	if got.LastUsedAt != nil {
		t.Errorf("LastUsedAt = %v, want nil before first use", got.LastUsedAt)
	}

	if empty, err := passkeys.ListByUser(ctx, "nobody"); err != nil || len(empty) != 0 {
		t.Errorf("ListByUser for an unknown user: %d rows, %v", len(empty), err)
	}
}

// credential_data is stored as TEXT, not a BLOB, so SQLite's own JSON
// functions can read it. A blob whose contents happen to be JSON would
// pass a round-trip test and still fail json_valid.
func TestWebAuthnStore_CredentialDataIsReadableJSON(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if err := NewWebAuthnStore(db).Add(ctx, store.WebAuthnCredential{
		ID: "wa-1", UserID: "user-1", CredentialID: []byte{1},
		CredentialData: []byte(`{"Authenticator":{"SignCount":7}}`),
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	var signCount int
	err := db.QueryRowContext(ctx,
		`SELECT json_extract(credential_data, '$.Authenticator.SignCount') FROM webauthn_credentials`).Scan(&signCount)
	if err != nil {
		t.Fatalf("json_extract: %v", err)
	}
	if signCount != 7 {
		t.Errorf("SignCount read back as %d, want 7", signCount)
	}
}

// Update is how the signature counter advances, and an advancing counter
// is the whole basis of cloned-authenticator detection. It matches on
// credential_id because that is what the login ceremony has in hand.
func TestWebAuthnStore_UpdateAdvancesStoredState(t *testing.T) {
	db := newTestDB(t)
	passkeys := NewWebAuthnStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	credID := []byte{0x0a, 0x0b}
	if err := passkeys.Add(ctx, store.WebAuthnCredential{
		ID: "wa-1", UserID: "user-1", CredentialID: credID,
		CredentialData: []byte(`{"SignCount":1}`), Nickname: "Phone",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if err := passkeys.Update(ctx, store.WebAuthnCredential{
		CredentialID: credID, CredentialData: []byte(`{"SignCount":2}`),
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	list, err := passkeys.ListByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d credentials, want 1 — Update inserted instead of updating", len(list))
	}
	if string(list[0].CredentialData) != `{"SignCount":2}` {
		t.Errorf("CredentialData = %s, want the updated counter", list[0].CredentialData)
	}
	if list[0].LastUsedAt == nil {
		t.Error("LastUsedAt is nil after Update")
	}
	// Nickname is not Update's business — it is user-supplied and would
	// be wiped by a login if Update overwrote it.
	if list[0].Nickname != "Phone" {
		t.Errorf("Nickname = %q, want Phone — Update should not touch it", list[0].Nickname)
	}

	if err := passkeys.Update(ctx, store.WebAuthnCredential{
		CredentialID: []byte{0xff}, CredentialData: []byte(`{}`),
	}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Update on an unknown credential: got %v, want store.ErrNotFound", err)
	}
}

// Delete is scoped by user as well as credential ID, so knowing someone
// else's credential ID is not enough to deregister their passkey.
func TestWebAuthnStore_DeleteIsScopedToTheOwner(t *testing.T) {
	db := newTestDB(t)
	passkeys := NewWebAuthnStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")
	seedUser(t, db, "user-2", "attacker@dev.com")

	credID := []byte{0x01, 0x02}
	if err := passkeys.Add(ctx, store.WebAuthnCredential{
		ID: "wa-1", UserID: "user-1", CredentialID: credID, CredentialData: []byte(`{}`),
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if err := passkeys.Delete(ctx, "user-2", credID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another user's Delete: got %v, want store.ErrNotFound", err)
	}
	if list, err := passkeys.ListByUser(ctx, "user-1"); err != nil || len(list) != 1 {
		t.Fatalf("the credential is gone after a foreign Delete: %d rows, %v", len(list), err)
	}

	if err := passkeys.Delete(ctx, "user-1", credID); err != nil {
		t.Fatalf("owner's Delete: %v", err)
	}
	if list, err := passkeys.ListByUser(ctx, "user-1"); err != nil || len(list) != 0 {
		t.Errorf("after Delete: %d rows, %v", len(list), err)
	}
}

func TestWebAuthnStore_DuplicateCredentialIDRejected(t *testing.T) {
	db := newTestDB(t)
	passkeys := NewWebAuthnStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")
	seedUser(t, db, "user-2", "other@dev.com")

	credID := []byte{0x07}
	if err := passkeys.Add(ctx, store.WebAuthnCredential{
		ID: "wa-1", UserID: "user-1", CredentialID: credID, CredentialData: []byte(`{}`),
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	err := passkeys.Add(ctx, store.WebAuthnCredential{
		ID: "wa-2", UserID: "user-2", CredentialID: credID, CredentialData: []byte(`{}`),
	})
	if err == nil {
		t.Error("the same credential ID was registered to a second user")
	}
}
