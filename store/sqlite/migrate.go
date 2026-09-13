package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migrationTable records which files have been applied. Prefixed so it
// is obviously not one of the host app's own tables — an embedded
// SQLite file is very often shared with the rest of the application,
// unlike a dedicated Postgres database.
const migrationTable = "cryden_schema_migrations"

// Migrate applies every embedded up-migration that has not run yet, in
// filename order, and records each one so a second call is a no-op.
//
// It exists here and not in store/postgres for a reason that is about
// SQLite rather than about consistency: a Postgres deployment already
// has psql and, usually, a migration tool in its pipeline, so shipping
// .sql files is enough. An embedded database frequently has neither —
// the whole appeal is one file and one binary — and telling a host app
// to find a way to pipe SQL into it before the engine will start would
// be handing back the problem this backend exists to remove. The same
// files are still on disk under migrations/ for anyone who prefers to
// apply them by hand.
//
// Each file is executed as one string, so the driver must accept
// multiple statements in a single Exec. mattn/go-sqlite3,
// modernc.org/sqlite and ncruces/go-sqlite3 all do.
//
// Each file also runs inside its own transaction. SQLite's DDL is
// transactional, so a file that fails halfway leaves no half-built
// schema and no marker claiming it ran.
func Migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS `+migrationTable+` (
			name       TEXT PRIMARY KEY NOT NULL,
			applied_at TEXT NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("sqlite: creating %s: %w", migrationTable, err)
	}

	applied, err := appliedMigrations(ctx, db)
	if err != nil {
		return err
	}

	names, err := upMigrationNames()
	if err != nil {
		return err
	}

	for _, name := range names {
		if applied[name] {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("sqlite: reading migration %s: %w", name, err)
		}
		if err := applyMigration(ctx, db, name, string(body)); err != nil {
			return err
		}
	}
	return nil
}

func applyMigration(ctx context.Context, db *sql.DB, name, body string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op once Commit succeeds

	if _, err := tx.ExecContext(ctx, body); err != nil {
		return fmt.Errorf("sqlite: applying migration %s: %w", name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO `+migrationTable+` (name, applied_at) VALUES (?, ?)`,
		name, formatTime(time.Now()),
	); err != nil {
		return fmt.Errorf("sqlite: recording migration %s: %w", name, err)
	}
	return tx.Commit()
}

func appliedMigrations(ctx context.Context, db *sql.DB) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM `+migrationTable)
	if err != nil {
		return nil, fmt.Errorf("sqlite: reading %s: %w", migrationTable, err)
	}
	defer rows.Close()

	applied := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		applied[name] = true
	}
	return applied, rows.Err()
}

// upMigrationNames returns the up-migrations sorted by filename, which
// is what makes the 0001/0002/... prefix load-bearing rather than
// decorative. Down-migrations are shipped for an operator to apply
// deliberately and are never run from here — an automatic rollback of a
// schema holding live credentials is not a thing this package should be
// able to do by accident.
func upMigrationNames() ([]string, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

// Pragma problems CheckPragmas reports. Sentinels rather than opaque
// strings so a host app can decide for itself which one is fatal —
// a single-threaded CLI tool genuinely does not need a busy timeout.
var (
	ErrForeignKeysDisabled = errors.New("sqlite: foreign key enforcement is off — set foreign_keys in the DSN")
	ErrNoBusyTimeout       = errors.New("sqlite: busy timeout is zero — a concurrent writer will fail immediately instead of waiting")
)

// CheckPragmas reports connection settings that would make this backend
// behave differently from the way it is documented, joined with
// errors.Join so one call names every problem rather than only the
// first. Returns nil when both are set.
//
// Call it once at startup, right after Migrate. It reads whichever
// pooled connection it is handed, which is sound for the case it exists
// to catch — a DSN-set pragma applies to every connection in the pool,
// so any one connection answers for all of them. It cannot detect the
// pathological case of a driver-level hook setting pragmas on only some
// connections, and does not try to.
func CheckPragmas(ctx context.Context, db *sql.DB) error {
	var problems []error

	var foreignKeys int
	if err := db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		return fmt.Errorf("sqlite: reading PRAGMA foreign_keys: %w", err)
	}
	if foreignKeys == 0 {
		problems = append(problems, ErrForeignKeysDisabled)
	}

	var busyTimeout int
	if err := db.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		return fmt.Errorf("sqlite: reading PRAGMA busy_timeout: %w", err)
	}
	if busyTimeout == 0 {
		problems = append(problems, ErrNoBusyTimeout)
	}

	return errors.Join(problems...)
}
