package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

func TestUserStore_CreateAndGet(t *testing.T) {
	db := newTestDB(t)
	users := NewUserStore(db)
	ctx := context.Background()

	if err := users.Create(ctx, store.User{
		ID: "user-1", Email: "raymondproguy@dev.com", PasswordHash: "hash-1",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	for _, tc := range []struct {
		name string
		get  func() (store.User, error)
	}{
		{"by ID", func() (store.User, error) { return users.GetByID(ctx, "user-1") }},
		{"by email", func() (store.User, error) { return users.GetByEmail(ctx, "raymondproguy@dev.com") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, err := tc.get()
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if u.Email != "raymondproguy@dev.com" || u.PasswordHash != "hash-1" {
				t.Errorf("wrong row back: %+v", u)
			}
			if u.LockedUntil != nil {
				t.Errorf("LockedUntil = %v, want nil for a new user", u.LockedUntil)
			}
			// Assigned by the store, not defaulted by the schema —
			// SQLite has no now(), so a zero value here means the Go
			// side forgot to supply one.
			if u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() {
				t.Errorf("timestamps not populated: created=%v updated=%v", u.CreatedAt, u.UpdatedAt)
			}
		})
	}
}

func TestUserStore_GetMissingIsErrNotFound(t *testing.T) {
	db := newTestDB(t)
	users := NewUserStore(db)
	ctx := context.Background()

	if _, err := users.GetByID(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetByID: got %v, want store.ErrNotFound", err)
	}
	if _, err := users.GetByEmail(ctx, "nobody@dev.com"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetByEmail: got %v, want store.ErrNotFound", err)
	}
}

func TestUserStore_DuplicateEmailRejected(t *testing.T) {
	db := newTestDB(t)
	users := NewUserStore(db)
	ctx := context.Background()

	seedUser(t, db, "user-1", "raymondproguy@dev.com")
	err := users.Create(ctx, store.User{ID: "user-2", Email: "raymondproguy@dev.com", PasswordHash: "h"})
	if err == nil {
		t.Fatal("second Create with the same email succeeded; the UNIQUE constraint is missing")
	}
}

func TestUserStore_UpdatesAndMissingRows(t *testing.T) {
	db := newTestDB(t)
	users := NewUserStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if err := users.UpdateEmail(ctx, "user-1", "new@dev.com"); err != nil {
		t.Fatalf("UpdateEmail: %v", err)
	}
	if err := users.UpdatePasswordHash(ctx, "user-1", "hash-2"); err != nil {
		t.Fatalf("UpdatePasswordHash: %v", err)
	}
	u, err := users.GetByEmail(ctx, "new@dev.com")
	if err != nil {
		t.Fatalf("GetByEmail after update: %v", err)
	}
	if u.PasswordHash != "hash-2" {
		t.Errorf("PasswordHash = %q, want hash-2", u.PasswordHash)
	}

	// Updating a row that isn't there must report it rather than
	// silently succeeding on zero rows.
	if err := users.UpdateEmail(ctx, "nobody", "x@dev.com"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("UpdateEmail on missing user: got %v, want store.ErrNotFound", err)
	}
	if err := users.UpdatePasswordHash(ctx, "nobody", "x"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("UpdatePasswordHash on missing user: got %v, want store.ErrNotFound", err)
	}
	if err := users.ResetFailedAttempts(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("ResetFailedAttempts on missing user: got %v, want store.ErrNotFound", err)
	}
	if err := users.LockAccount(ctx, "nobody", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("LockAccount on missing user: got %v, want store.ErrNotFound", err)
	}
	if err := users.Delete(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Delete on missing user: got %v, want store.ErrNotFound", err)
	}
}

// The counter is the one method Postgres implements with
// UPDATE ... RETURNING and this backend cannot, so the value coming
// back out is exactly what needs checking: lockout compares it against
// a threshold, and an off-by-one there is an account locked a login too
// early or too late.
func TestUserStore_IncrementFailedAttemptsReturnsNewValue(t *testing.T) {
	db := newTestDB(t)
	users := NewUserStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	for want := 1; want <= 3; want++ {
		got, err := users.IncrementFailedAttempts(ctx, "user-1")
		if err != nil {
			t.Fatalf("IncrementFailedAttempts: %v", err)
		}
		if got != want {
			t.Fatalf("attempt %d returned %d", want, got)
		}
	}

	u, err := users.GetByID(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if u.FailedAttempts != 3 {
		t.Errorf("persisted FailedAttempts = %d, want 3", u.FailedAttempts)
	}

	if _, err := users.IncrementFailedAttempts(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("increment on missing user: got %v, want store.ErrNotFound", err)
	}
}

func TestUserStore_LockAndResetClearsBoth(t *testing.T) {
	db := newTestDB(t)
	users := NewUserStore(db)
	ctx := context.Background()
	seedUser(t, db, "user-1", "raymondproguy@dev.com")

	if _, err := users.IncrementFailedAttempts(ctx, "user-1"); err != nil {
		t.Fatalf("increment: %v", err)
	}
	until := time.Now().Add(15 * time.Minute)
	if err := users.LockAccount(ctx, "user-1", until); err != nil {
		t.Fatalf("LockAccount: %v", err)
	}

	u, err := users.GetByID(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if u.LockedUntil == nil {
		t.Fatal("LockedUntil is nil after LockAccount")
	}
	// Exact, not approximate: the TEXT format carries all nine
	// fractional digits, so a caller-supplied instant round-trips
	// whole. An approximate assertion here would hide a truncating
	// format.
	if !u.LockedUntil.Equal(until) {
		t.Errorf("LockedUntil = %v, want %v", u.LockedUntil, until)
	}

	// A successful login resets both halves. Leaving locked_until set
	// would lock out a user who just proved their password.
	if err := users.ResetFailedAttempts(ctx, "user-1"); err != nil {
		t.Fatalf("ResetFailedAttempts: %v", err)
	}
	u, err = users.GetByID(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if u.FailedAttempts != 0 || u.LockedUntil != nil {
		t.Errorf("after reset: attempts=%d lockedUntil=%v, want 0 and nil", u.FailedAttempts, u.LockedUntil)
	}
}

func TestUserStore_ListAllAndCount(t *testing.T) {
	db := newTestDB(t)
	users := NewUserStore(db)
	ctx := context.Background()

	if n, err := users.Count(ctx); err != nil || n != 0 {
		t.Fatalf("Count on empty: %d, %v", n, err)
	}
	for i := 0; i < 5; i++ {
		seedUser(t, db, string(rune('a'+i))+"-id", string(rune('a'+i))+"@dev.com")
		// Create assigns created_at from the clock, and ListAll orders
		// by it, so consecutive inserts need distinguishable instants.
		time.Sleep(time.Millisecond)
	}

	if n, err := users.Count(ctx); err != nil || n != 5 {
		t.Fatalf("Count = %d, %v; want 5", n, err)
	}

	page, err := users.ListAll(ctx, 2, 0)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(page) != 2 {
		t.Fatalf("first page has %d rows, want 2", len(page))
	}
	// Newest first, matching Postgres.
	if page[0].ID != "e-id" || page[1].ID != "d-id" {
		t.Errorf("first page = %s, %s; want e-id, d-id", page[0].ID, page[1].ID)
	}

	page2, err := users.ListAll(ctx, 2, 2)
	if err != nil {
		t.Fatalf("ListAll offset 2: %v", err)
	}
	if len(page2) != 2 || page2[0].ID != "c-id" {
		t.Errorf("second page = %+v", page2)
	}

	if empty, err := users.ListAll(ctx, 2, 99); err != nil || len(empty) != 0 {
		t.Errorf("ListAll past the end: %d rows, %v", len(empty), err)
	}
}

// Delete's cascade is written by hand precisely so it does not depend on
// the host's DSN, so the test that matters runs with foreign keys OFF —
// SQLite's own default. With FKs on, the declared ON DELETE clauses
// would pass this test even if UserStore.Delete deleted nothing but the
// user row, which is the bug being guarded against: sessions surviving
// their user means refresh tokens that keep rotating for an account that
// no longer exists.
func TestUserStore_DeleteCascadesWithForeignKeysOff(t *testing.T) {
	db := newTestDBWithoutForeignKeys(t)
	ctx := context.Background()

	// Prove the premise before relying on it. If a future driver or
	// default turns FKs on for a bare DSN, this test stops testing what
	// it claims to and should say so rather than passing quietly.
	var fkOn int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fkOn); err != nil {
		t.Fatalf("reading pragma: %v", err)
	}
	if fkOn != 0 {
		t.Fatalf("foreign_keys = %d on a bare DSN; this test needs them off to mean anything", fkOn)
	}

	seedUser(t, db, "user-1", "raymondproguy@dev.com")
	seedUser(t, db, "user-2", "other@dev.com")

	if err := NewSessionStore(db).Create(ctx, store.Session{
		ID: "sess-1", FamilyID: "sess-1", UserID: "user-1", TokenHash: "th-1",
	}); err != nil {
		t.Fatalf("session Create: %v", err)
	}
	if err := NewVerificationStore(db).Create(ctx, store.VerificationToken{
		ID: "vt-1", UserID: "user-1", Purpose: store.PurposeEmailVerify,
		TokenHash: "vth-1", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("verification Create: %v", err)
	}
	if err := NewOAuthStore(db).Link(ctx, store.OAuthIdentity{
		ID: "oi-1", UserID: "user-1", Provider: "google", ExternalID: "ext-1", Email: "raymondproguy@dev.com",
	}); err != nil {
		t.Fatalf("oauth Link: %v", err)
	}
	if err := NewTOTPStore(db).Upsert(ctx, store.TOTPSecret{UserID: "user-1", EncryptedSecret: "enc"}); err != nil {
		t.Fatalf("totp Upsert: %v", err)
	}
	if err := NewWebAuthnStore(db).Add(ctx, store.WebAuthnCredential{
		ID: "wa-1", UserID: "user-1", CredentialID: []byte{1, 2, 3}, CredentialData: []byte(`{"a":1}`),
	}); err != nil {
		t.Fatalf("webauthn Add: %v", err)
	}
	if err := NewRecoveryCodeStore(db).ReplaceAll(ctx, "user-1", []store.RecoveryCode{{CodeHash: "rc-1"}}); err != nil {
		t.Fatalf("recovery ReplaceAll: %v", err)
	}

	// A session belonging to someone else, to catch a cascade that
	// deletes more than it should.
	if err := NewSessionStore(db).Create(ctx, store.Session{
		ID: "sess-2", FamilyID: "sess-2", UserID: "user-2", TokenHash: "th-2",
	}); err != nil {
		t.Fatalf("session Create for user-2: %v", err)
	}

	// These two are SET NULL rather than deleted: the security record
	// outlives the account it describes.
	if err := NewAuditStore(db).Record(ctx, store.AuditEvent{
		Type: store.EventLoginSuccess, UserID: "user-1", IP: "1.2.3.4",
	}); err != nil {
		t.Fatalf("audit Record: %v", err)
	}
	if err := NewAnomalyStore(db).RecordAttempt(ctx, store.LoginAttempt{
		UserID: "user-1", IP: "1.2.3.4", Outcome: store.OutcomeFailure,
	}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}

	if err := NewUserStore(db).Delete(ctx, "user-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	for _, table := range []string{
		"sessions", "verification_tokens", "oauth_identities",
		"totp_secrets", "webauthn_credentials", "recovery_codes",
	} {
		var n int
		if err := db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM "+table+" WHERE user_id = 'user-1'").Scan(&n); err != nil {
			t.Fatalf("counting %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s still holds %d row(s) for the deleted user", table, n)
		}
	}

	for _, table := range []string{"audit_events", "login_attempts"} {
		var total, orphaned int
		if err := db.QueryRowContext(ctx,
			"SELECT COUNT(*), COUNT(CASE WHEN user_id IS NULL THEN 1 END) FROM "+table).Scan(&total, &orphaned); err != nil {
			t.Fatalf("counting %s: %v", table, err)
		}
		if total != 1 || orphaned != 1 {
			t.Errorf("%s: %d row(s), %d with a NULL user_id; want 1 and 1 — the record should survive, detached", table, total, orphaned)
		}
	}

	var otherSessions int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sessions WHERE user_id = 'user-2'").Scan(&otherSessions); err != nil {
		t.Fatalf("counting user-2 sessions: %v", err)
	}
	if otherSessions != 1 {
		t.Errorf("user-2 has %d sessions, want 1 — the cascade took rows it did not own", otherSessions)
	}

	if _, err := NewUserStore(db).GetByID(ctx, "user-2"); err != nil {
		t.Errorf("user-2 should still exist: %v", err)
	}
}
