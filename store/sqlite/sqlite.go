// Package sqlite implements every store interface in
// github.com/crydensync/cryden/v2/store against SQLite, as a second
// production backend alongside store/postgres.
//
// # No driver is imported here
//
// Unlike store/postgres, which blank-imports lib/pq, this package
// imports no SQLite driver at all and speaks only database/sql. That is
// deliberate: SQLite's Go drivers differ in ways a host app has to live
// with and this library has no business deciding — mattn/go-sqlite3
// needs cgo and a C toolchain, modernc.org/sqlite is pure Go but adds
// a large generated dependency tree, ncruces/go-sqlite3 runs the real
// amalgamation under a wasm runtime. Forcing any one of them on every
// consumer of the engine, including the ones running Postgres, would be
// a cost with no matching benefit. Register whichever you prefer and
// pass the *sql.DB in:
//
//	import _ "modernc.org/sqlite"
//
//	db, err := sql.Open("sqlite", "file:auth.db?"+
//	    "_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
//	...
//	users := sqlite.NewUserStore(db)
//
// As in store/postgres, the caller owns the connection's lifecycle;
// nothing here opens or closes a database.
//
// # Those DSN pragmas are not decoration
//
// SQLite pragmas are per-connection, and *sql.DB is a pool, so the only
// place they can be set for every connection is the DSN (the parameter
// syntax above is modernc's; mattn spells it _foreign_keys=on&
// _busy_timeout=5000). Three matter here:
//
//   - foreign_keys, off by default, is what makes the schema's ON
//     DELETE clauses run at all. UserStore.Delete deliberately does not
//     depend on it (see that method), but audit_events and
//     login_attempts rows still expect their ON DELETE SET NULL.
//   - busy_timeout, 0 by default, is what stops a second writer getting
//     an immediate SQLITE_BUSY instead of waiting its turn. Any app
//     serving two requests at once wants this.
//   - journal_mode(WAL) lets readers proceed during a write. Unlike the
//     other two it is persistent in the database file, so it only has
//     to be set once, but setting it in the DSN is harmless and clearer.
//
// CheckPragmas reports the first two at startup so a missing one fails
// loudly instead of quietly changing behaviour.
//
// # Timestamps are TEXT
//
// Every timestamp column is TEXT holding RFC 3339 in UTC with a fixed
// nine fractional digits, written and parsed by this package rather
// than by the driver — see the migration's header comment for why, and
// for the two type conventions that go with it.
package sqlite

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/crydensync/cryden/v2/store"
)

// timeLayout is RFC 3339 with the fractional part pinned to nine
// digits. time.RFC3339Nano cannot be used for writing: it trims
// trailing zeros, so ".100000000" and ".1" would both appear in the
// column and string comparison would order them wrongly against each
// other. Reading accepts either, since RFC3339Nano parses both and a
// row edited by hand should still load.
const timeLayout = "2006-01-02T15:04:05.000000000Z07:00"

// formatTime renders t for storage. UTC first, always: the layout ends
// in a numeric zone offset, and two rows written from machines in
// different zones would otherwise compare by their text rather than by
// the instant they name.
func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

// scanTime reads one TEXT timestamp column, nullable or not.
// sql.NullTime is unusable here — the column is TEXT, so a driver hands
// back a string and parsing it is this package's job.
type scanTime struct {
	Time  time.Time
	Valid bool
}

func (s *scanTime) Scan(src any) error {
	var raw string
	switch v := src.(type) {
	case nil:
		s.Time, s.Valid = time.Time{}, false
		return nil
	case string:
		raw = v
	case []byte:
		raw = string(v)
	case time.Time:
		// Only reachable if a driver converts the column itself, which
		// is what declaring these columns TEXT is meant to prevent.
		// Accepted rather than rejected: a host that swaps drivers
		// should not get scan errors out of it.
		s.Time, s.Valid = v, true
		return nil
	default:
		return fmt.Errorf("sqlite: cannot read timestamp from %T", src)
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return fmt.Errorf("sqlite: unreadable timestamp %q: %w", raw, err)
	}
	s.Time, s.Valid = t, true
	return nil
}

// ptr is for the domain types' *time.Time fields, where nil is the
// meaningful value: a NULL revoked_at/used_at/confirmed_at means "not
// yet", never a zero instant.
func (s scanTime) ptr() *time.Time {
	if !s.Valid {
		return nil
	}
	t := s.Time
	return &t
}

// newID generates a row identifier for the two tables whose interface
// contract puts that on the implementation (AuditStore.Record and
// AnomalyStore.RecordAttempt) — Postgres calls gen_random_uuid() in the
// statement itself, which SQLite has no equivalent of. UUIDv7 to match
// every other ID the engine writes, so one table's keys stay
// time-ordered whichever layer produced them.
func newID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// checkRowsAffected converts a zero-rows-affected UPDATE/DELETE into
// store.ErrNotFound, so callers get consistent not-found semantics
// regardless of which store method or which backend they called.
func checkRowsAffected(result sql.Result) error {
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// nullString maps a Go "" to a real SQL NULL, for the columns where
// absent and empty are different things — a login_failed event for an
// email with no account behind it has no user to attribute to.
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// formatTimePtr renders an optional timestamp for storage, mapping nil
// or the zero instant to SQL NULL. The pair of it and scanTime.ptr is
// how the domain types' *time.Time fields survive a round trip through
// a TEXT column with "not set" intact.
func formatTimePtr(t *time.Time) sql.NullString {
	if t == nil || t.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: formatTime(*t), Valid: true}
}
