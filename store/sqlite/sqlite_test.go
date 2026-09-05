package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/crydensync/cryden/v2/store"
)

// The driver these tests register is modernc.org/sqlite, chosen because
// it is pure Go: `go test ./...` then works with CGO_ENABLED=0, which is
// the default in a lot of CI images and every scratch container. The
// package under test imports no driver at all (see its doc comment), so
// this choice binds the tests and nothing else.

var dbCounter atomic.Int64

// newTestDB returns a migrated, pragma-configured database. On-disk
// under t.TempDir() rather than in memory: a file is what a host app
// actually runs, it exercises the WAL and busy-timeout settings that
// only exist on real files, and t.TempDir() removes it afterwards
// anyway. The counter keeps parallel tests off each other's file.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), fmt.Sprintf("cryden-%d.db", dbCounter.Add(1)))
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := CheckPragmas(ctx, db); err != nil {
		t.Fatalf("CheckPragmas on a freshly configured DSN: %v", err)
	}
	return db
}

// seedUser inserts a user directly, for the stores whose rows reference
// one. Every table but users has a foreign key into it, and foreign
// keys are ON in newTestDB, so this is not optional setup.
func seedUser(t *testing.T, db *sql.DB, id, email string) {
	t.Helper()
	users := NewUserStore(db)
	err := users.Create(context.Background(), store.User{
		ID:           id,
		Email:        email,
		PasswordHash: "$2a$04$notarealhashjustplaceholderxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	})
	if err != nil {
		t.Fatalf("seeding user %s: %v", id, err)
	}
}

func TestMigrate_IsIdempotent(t *testing.T) {
	db := newTestDB(t) // already migrated once
	ctx := context.Background()

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("third Migrate: %v", err)
	}

	var applied int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+migrationTable).Scan(&applied); err != nil {
		t.Fatalf("counting applied migrations: %v", err)
	}
	if applied != 1 {
		t.Errorf("expected 1 recorded migration after three calls, got %d", applied)
	}
}

func TestMigrate_CreatesEveryTableAndPartialIndex(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, table := range []string{
		"users", "sessions", "audit_events", "verification_tokens",
		"oauth_identities", "totp_secrets", "webauthn_credentials",
		"recovery_codes", "login_attempts",
	} {
		var name string
		err := db.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
		if err != nil {
			t.Errorf("table %s missing: %v", table, err)
		}
	}

	// The partial indexes are the entire justification for
	// login_attempts existing as its own table rather than as more
	// audit_events queries, so their presence is worth asserting
	// rather than assuming the DDL was accepted.
	for _, index := range []string{
		"idx_sessions_user_active",
		"idx_login_attempts_user_failures",
		"idx_login_attempts_ip_failures",
		"idx_login_attempts_user_successes",
	} {
		var sqlText string
		err := db.QueryRowContext(ctx,
			`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?`, index).Scan(&sqlText)
		if err != nil {
			t.Errorf("index %s missing: %v", index, err)
			continue
		}
		if !strings.Contains(sqlText, "WHERE") {
			t.Errorf("index %s is not partial: %s", index, sqlText)
		}
	}
}

func TestCheckPragmas_ReportsBothProblems(t *testing.T) {
	// A DSN with neither pragma — the default a host gets by writing the
	// obvious sql.Open("sqlite", path) and nothing more.
	path := filepath.Join(t.TempDir(), "bare.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	err = CheckPragmas(context.Background(), db)
	if err == nil {
		t.Fatal("expected CheckPragmas to object to a bare DSN")
	}
	if !errors.Is(err, ErrForeignKeysDisabled) {
		t.Errorf("expected ErrForeignKeysDisabled, got %v", err)
	}
	if !errors.Is(err, ErrNoBusyTimeout) {
		t.Errorf("expected ErrNoBusyTimeout, got %v", err)
	}
}

func TestTimestampRoundTrip(t *testing.T) {
	// The whole schema depends on this: nanosecond precision survives,
	// and the stored text is fixed-width so string comparison orders
	// rows the way time does.
	db := newTestDB(t)
	ctx := context.Background()

	// A time with a fractional part whose trailing zeros
	// time.RFC3339Nano would have trimmed.
	when := time.Date(2026, 9, 5, 12, 34, 56, 100000000, time.UTC)
	seedUser(t, db, "user-ts", "raymondproguy@dev.com")

	users := NewUserStore(db)
	if err := users.LockAccount(ctx, "user-ts", when); err != nil {
		t.Fatalf("LockAccount: %v", err)
	}

	var raw string
	if err := db.QueryRowContext(ctx, `SELECT locked_until FROM users WHERE id = ?`, "user-ts").Scan(&raw); err != nil {
		t.Fatalf("reading raw column: %v", err)
	}
	if want := "2026-09-05T12:34:56.100000000Z"; raw != want {
		t.Errorf("stored timestamp = %q, want %q", raw, want)
	}
	if len(raw) != 30 {
		t.Errorf("stored timestamp is %d chars, want a fixed 30", len(raw))
	}

	got, err := users.GetByID(ctx, "user-ts")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.LockedUntil == nil || !got.LockedUntil.Equal(when) {
		t.Errorf("LockedUntil round-tripped as %v, want %v", got.LockedUntil, when)
	}
}

func TestTimestampOrderingIsLexicographic(t *testing.T) {
	// Written out of order on purpose: if the format were not
	// fixed-width, ORDER BY created_at DESC would disagree with
	// chronology and every "most recent" query in the package would be
	// subtly wrong.
	db := newTestDB(t)
	ctx := context.Background()
	seedUser(t, db, "user-ord", "raymondproguy@dev.com")

	// Written with raw SQL, not Create: created_at is store-assigned in
	// every implementation (Postgres defaults it to now()), so the only
	// way to pin the instants this test is about is to write them.
	base := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	offsets := []time.Duration{500 * time.Millisecond, 5 * time.Nanosecond, 2 * time.Second, 50 * time.Microsecond}
	for i, off := range offsets {
		_, err := db.ExecContext(ctx, `
			INSERT INTO sessions (id, family_id, user_id, token_hash, ip, user_agent, created_at)
			VALUES (?, 'fam', 'user-ord', ?, '', '', ?)
		`, fmt.Sprintf("sess-%d", i), fmt.Sprintf("hash-%d", i), formatTime(base.Add(off)))
		if err != nil {
			t.Fatalf("inserting session %d: %v", i, err)
		}
	}

	sessions := NewSessionStore(db)

	got, err := sessions.ListByUser(ctx, "user-ord")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(got) != len(offsets) {
		t.Fatalf("expected %d sessions, got %d", len(offsets), len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].CreatedAt.After(got[i-1].CreatedAt) {
			t.Errorf("session %d (%v) is newer than the one before it (%v) — newest-first order is broken",
				i, got[i].CreatedAt, got[i-1].CreatedAt)
		}
	}
}

// newTestDBWithoutForeignKeys is newTestDB with the foreign_keys pragma
// left at SQLite's own default, which is OFF. Not an oversight: it is
// the configuration UserStore.Delete's hand-written cascade exists to
// survive, so at least one test has to run in it. CheckPragmas is not
// called here — it would correctly complain.
func newTestDBWithoutForeignKeys(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), fmt.Sprintf("cryden-nofk-%d.db", dbCounter.Add(1)))

	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}
