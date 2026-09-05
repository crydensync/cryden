package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

func newSession(id, family, user, hash string) store.Session {
	return store.Session{
		ID: id, FamilyID: family, UserID: user, TokenHash: hash,
		IP: "1.2.3.4", UserAgent: "test-agent",
	}
}

func TestSessionStore_CreateAndLookups(t *testing.T) {
	db := newTestDB(t)
	sessions := NewSessionStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if err := sessions.Create(ctx, newSession("sess-1", "sess-1", "user-1", "th-1")); err != nil {
		t.Fatalf("Create: %v", err)
	}

	byID, err := sessions.GetByID(ctx, "sess-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	byHash, err := sessions.GetByTokenHash(ctx, "th-1")
	if err != nil {
		t.Fatalf("GetByTokenHash: %v", err)
	}
	if byID.ID != byHash.ID {
		t.Errorf("the two lookups disagree: %q vs %q", byID.ID, byHash.ID)
	}
	if byID.IP != "1.2.3.4" || byID.UserAgent != "test-agent" {
		t.Errorf("IP/UserAgent not round-tripped: %+v", byID)
	}
	if byID.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero; the store must assign it")
	}
	if byID.RevokedAt != nil {
		t.Errorf("RevokedAt = %v, want nil for a fresh session", byID.RevokedAt)
	}

	if _, err := sessions.GetByID(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetByID missing: got %v, want store.ErrNotFound", err)
	}
	if _, err := sessions.GetByTokenHash(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetByTokenHash missing: got %v, want store.ErrNotFound", err)
	}
}

// The lookups must keep finding revoked sessions. Refresh-token reuse
// detection works by looking up the presented token and noticing the
// session it belongs to is already dead — a lookup that filtered
// revoked rows out would turn a detected replay attack into an ordinary
// "not found" and lose the whole signal.
func TestSessionStore_LookupsStillFindRevokedSessions(t *testing.T) {
	db := newTestDB(t)
	sessions := NewSessionStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if err := sessions.Create(ctx, newSession("sess-1", "sess-1", "user-1", "th-1")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := sessions.Revoke(ctx, "sess-1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := sessions.GetByTokenHash(ctx, "th-1")
	if err != nil {
		t.Fatalf("GetByTokenHash on a revoked session: %v", err)
	}
	if got.RevokedAt == nil {
		t.Error("RevokedAt is nil after Revoke")
	}

	// Revoking twice reports the second as a no-op, matching Postgres.
	if err := sessions.Revoke(ctx, "sess-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second Revoke: got %v, want store.ErrNotFound", err)
	}
	if err := sessions.Revoke(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Revoke missing: got %v, want store.ErrNotFound", err)
	}
}

func TestSessionStore_ListByUserExcludesRevoked(t *testing.T) {
	db := newTestDB(t)
	sessions := NewSessionStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")
	seedUser(t, db, "user-2", "other@dev.com")

	for i, id := range []string{"sess-1", "sess-2", "sess-3"} {
		if err := sessions.Create(ctx, newSession(id, id, "user-1", "th-"+id)); err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
		time.Sleep(time.Millisecond)
	}
	if err := sessions.Create(ctx, newSession("other", "other", "user-2", "th-other")); err != nil {
		t.Fatalf("Create for user-2: %v", err)
	}
	if err := sessions.Revoke(ctx, "sess-2"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	list, err := sessions.ListByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d sessions, want 2 (one of three revoked)", len(list))
	}
	// Newest first.
	if list[0].ID != "sess-3" || list[1].ID != "sess-1" {
		t.Errorf("order = %s, %s; want sess-3, sess-1", list[0].ID, list[1].ID)
	}
	for _, s := range list {
		if s.UserID != "user-1" {
			t.Errorf("another user's session leaked in: %+v", s)
		}
	}

	if empty, err := sessions.ListByUser(ctx, "nobody"); err != nil || len(empty) != 0 {
		t.Errorf("ListByUser for an unknown user: %d rows, %v", len(empty), err)
	}
}

func TestSessionStore_RevokeFamilyAndAllForUser(t *testing.T) {
	db := newTestDB(t)
	sessions := NewSessionStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	// Two rotation families for one user: revoking one must not touch
	// the other, which is the whole point of family_id.
	for _, s := range []store.Session{
		newSession("a1", "fam-a", "user-1", "th-a1"),
		newSession("a2", "fam-a", "user-1", "th-a2"),
		newSession("b1", "fam-b", "user-1", "th-b1"),
	} {
		if err := sessions.Create(ctx, s); err != nil {
			t.Fatalf("Create %s: %v", s.ID, err)
		}
	}

	if err := sessions.RevokeFamily(ctx, "fam-a"); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	list, err := sessions.ListByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 1 || list[0].ID != "b1" {
		t.Fatalf("after RevokeFamily(fam-a): %+v; want only b1", list)
	}

	// Incident response, not a lookup: a family already fully revoked,
	// or one that never existed, is not an error.
	if err := sessions.RevokeFamily(ctx, "fam-a"); err != nil {
		t.Errorf("second RevokeFamily: %v", err)
	}
	if err := sessions.RevokeFamily(ctx, "no-such-family"); err != nil {
		t.Errorf("RevokeFamily on an unknown family: %v", err)
	}

	if err := sessions.RevokeAllForUser(ctx, "user-1"); err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}
	if list, err = sessions.ListByUser(ctx, "user-1"); err != nil || len(list) != 0 {
		t.Errorf("after RevokeAllForUser: %d active, %v", len(list), err)
	}
	if err := sessions.RevokeAllForUser(ctx, "nobody"); err != nil {
		t.Errorf("RevokeAllForUser on an unknown user: %v", err)
	}
}

func TestSessionStore_RotateToken(t *testing.T) {
	db := newTestDB(t)
	sessions := NewSessionStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if err := sessions.Create(ctx, newSession("sess-1", "fam-1", "user-1", "th-1")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := sessions.RotateToken(ctx, "sess-1", newSession("sess-2", "fam-1", "user-1", "th-2")); err != nil {
		t.Fatalf("RotateToken: %v", err)
	}

	old, err := sessions.GetByID(ctx, "sess-1")
	if err != nil {
		t.Fatalf("GetByID old: %v", err)
	}
	if old.RevokedAt == nil {
		t.Error("the rotated-out session is not revoked")
	}
	fresh, err := sessions.GetByTokenHash(ctx, "th-2")
	if err != nil {
		t.Fatalf("GetByTokenHash new: %v", err)
	}
	// The family carries over — that is what lets reuse of any token in
	// the chain revoke the whole chain.
	if fresh.FamilyID != "fam-1" {
		t.Errorf("FamilyID = %q, want fam-1", fresh.FamilyID)
	}
}

// Rotation is a transaction, so a failure in its second half must leave
// the first half undone. A duplicate token_hash is the cheapest way to
// make the insert fail after the revoke has already run.
func TestSessionStore_RotateTokenRollsBackOnInsertFailure(t *testing.T) {
	db := newTestDB(t)
	sessions := NewSessionStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if err := sessions.Create(ctx, newSession("sess-1", "fam-1", "user-1", "th-1")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := sessions.Create(ctx, newSession("taken", "fam-x", "user-1", "th-taken")); err != nil {
		t.Fatalf("Create the colliding row: %v", err)
	}

	err := sessions.RotateToken(ctx, "sess-1", newSession("sess-2", "fam-1", "user-1", "th-taken"))
	if err == nil {
		t.Fatal("RotateToken succeeded with a duplicate token hash")
	}

	// The old session must still be live: the user's refresh token was
	// never replaced, so revoking it would have logged them out for a
	// failure that was not their fault.
	old, err := sessions.GetByID(ctx, "sess-1")
	if err != nil {
		t.Fatalf("GetByID after the failed rotation: %v", err)
	}
	if old.RevokedAt != nil {
		t.Errorf("the old session was revoked despite the rotation failing: RevokedAt = %v", old.RevokedAt)
	}
	if _, err := sessions.GetByID(ctx, "sess-2"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the new session exists after a failed rotation: %v", err)
	}

	if err := sessions.RotateToken(ctx, "nope", newSession("s", "f", "user-1", "th-z")); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RotateToken on a missing session: got %v, want store.ErrNotFound", err)
	}
}

// CountActive is system-wide, not per user — the interface says so, and
// an implementation that quietly scoped it to one user would still look
// right in a single-user test.
func TestSessionStore_CountActiveIsSystemWide(t *testing.T) {
	db := newTestDB(t)
	sessions := NewSessionStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")
	seedUser(t, db, "user-2", "other@dev.com")

	if n, err := sessions.CountActive(ctx); err != nil || n != 0 {
		t.Fatalf("CountActive on empty: %d, %v", n, err)
	}
	for _, s := range []store.Session{
		newSession("a", "a", "user-1", "th-a"),
		newSession("b", "b", "user-1", "th-b"),
		newSession("c", "c", "user-2", "th-c"),
	} {
		if err := sessions.Create(ctx, s); err != nil {
			t.Fatalf("Create %s: %v", s.ID, err)
		}
	}
	if n, err := sessions.CountActive(ctx); err != nil || n != 3 {
		t.Fatalf("CountActive = %d, %v; want 3 across both users", n, err)
	}
	if err := sessions.Revoke(ctx, "c"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if n, err := sessions.CountActive(ctx); err != nil || n != 2 {
		t.Errorf("CountActive after one revoke = %d, %v; want 2", n, err)
	}
}

// Sessions reference users, and the reference is declared NOT NULL with
// a foreign key. With the pragma on — the configuration hosts are told
// to use — a session for a nonexistent user must be refused rather than
// silently stored.
func TestSessionStore_ForeignKeyIsEnforcedWhenPragmaIsOn(t *testing.T) {
	db := newTestDB(t)
	err := NewSessionStore(db).Create(context.Background(),
		newSession("sess-1", "sess-1", "ghost-user", "th-1"))
	if err == nil {
		t.Fatal("a session for a nonexistent user was accepted; the foreign_keys pragma is not taking effect")
	}
}
