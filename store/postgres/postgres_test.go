package postgres

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// setupTestDB connects to the database in DATABASE_URL. If it's not
// set, the calling test is skipped (not failed) — this lets `go test
// ./...` pass in environments with no Postgres available, while still
// running real integration tests wherever DATABASE_URL is provided
// (CI, or locally against Supabase/Docker/whatever).
//
// Run the migration in migrations/0001_initial_schema.up.sql against
// this database before running these tests.
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — skipping Postgres integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("failed to open DB connection: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("failed to ping DB — is DATABASE_URL correct and migrations applied? %v", err)
	}
	return db
}
