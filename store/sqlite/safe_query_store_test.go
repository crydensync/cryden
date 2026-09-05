package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/ai"
	"github.com/crydensync/cryden/v2/store"
)

// newSeededQueryDB returns a SafeQueryStore over a database holding a
// small, known population, plus the read-write handle that built it and
// the file's path (the read-only test needs to reopen it).
func newSeededQueryDB(t *testing.T) (*SafeQueryStore, *sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), fmt.Sprintf("cryden-q-%d.db", dbCounter.Add(1)))
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	users := NewUserStore(db)
	sessions := NewSessionStore(db)
	audit := NewAuditStore(db)

	for i, u := range []struct {
		id, email string
		failed    int
	}{
		{"user-1", "raymondproguy@dev.com", 0},
		{"user-2", "raymond.other@dev.com", 4},
		{"user-3", "someoneelse@example.org", 1},
	} {
		if err := users.Create(ctx, store.User{
			ID:           u.id,
			Email:        u.email,
			PasswordHash: fmt.Sprintf("$2a$04$hash-that-must-never-be-queryable-%d", i),
		}); err != nil {
			t.Fatalf("seeding %s: %v", u.id, err)
		}
		if u.failed > 0 {
			for n := 0; n < u.failed; n++ {
				if _, err := users.IncrementFailedAttempts(ctx, u.id); err != nil {
					t.Fatalf("IncrementFailedAttempts: %v", err)
				}
			}
		}
	}

	for _, s := range []store.Session{
		{ID: "sess-1", FamilyID: "sess-1", UserID: "user-1", TokenHash: "hash-1", IP: "10.0.0.1", UserAgent: "Firefox"},
		{ID: "sess-2", FamilyID: "sess-2", UserID: "user-1", TokenHash: "hash-2", IP: "10.0.0.2", UserAgent: "Safari"},
		{ID: "sess-3", FamilyID: "sess-3", UserID: "user-2", TokenHash: "hash-3", IP: "10.0.0.1", UserAgent: "Firefox"},
	} {
		if err := sessions.Create(ctx, s); err != nil {
			t.Fatalf("seeding %s: %v", s.ID, err)
		}
	}

	for _, e := range []store.AuditEvent{
		{Type: store.EventLoginSuccess, UserID: "user-1", IP: "10.0.0.1"},
		{Type: store.EventLoginFailed, UserID: "user-2", IP: "10.0.0.9"},
		{Type: store.EventLoginFailed, UserID: "user-2", IP: "10.0.0.9"},
		{Type: store.EventLoginFailed, IP: "10.0.0.9"},
	} {
		if err := audit.Record(ctx, e); err != nil {
			t.Fatalf("seeding audit event: %v", err)
		}
	}

	return NewSafeQueryStore(db), db, path
}

func TestSafeQueryStore_SelectReturnsTheEntitysColumns(t *testing.T) {
	q, _, _ := newSeededQueryDB(t)

	for entity, want := range ai.EntityColumns {
		got, err := q.RunSafeQuery(context.Background(), ai.QueryIntent{Entity: entity})
		if err != nil {
			t.Fatalf("%s: %v", entity, err)
		}
		if strings.Join(got.Columns, ",") != strings.Join(want, ",") {
			t.Errorf("%s columns = %v, want %v", entity, got.Columns, want)
		}
		if len(got.Rows) == 0 {
			t.Errorf("%s returned no rows; the fixture seeds some", entity)
		}
		for _, row := range got.Rows {
			if len(row) != len(want) {
				t.Errorf("%s row has %d cells for %d columns", entity, len(row), len(want))
			}
		}
	}
}

// The hashes are the point of the allowlist. Neither the column list nor
// any single returned cell may carry one, and asking for one by name has
// to be refused rather than quietly dropped.
func TestSafeQueryStore_HashesAreUnreachable(t *testing.T) {
	q, _, _ := newSeededQueryDB(t)
	ctx := context.Background()

	for _, entity := range []string{"users", "sessions"} {
		got, err := q.RunSafeQuery(ctx, ai.QueryIntent{Entity: entity})
		if err != nil {
			t.Fatalf("%s: %v", entity, err)
		}
		for _, c := range got.Columns {
			if c == "password_hash" || c == "token_hash" {
				t.Errorf("%s exposes column %q", entity, c)
			}
		}
		for _, row := range got.Rows {
			for _, cell := range row {
				if strings.Contains(cell, "must-never-be-queryable") || strings.HasPrefix(cell, "hash-") {
					t.Errorf("%s leaked a hash in a returned cell: %q", entity, cell)
				}
			}
		}
	}

	// And by name, as a filter field.
	if _, err := q.RunSafeQuery(ctx, ai.QueryIntent{
		Entity:  "users",
		Filters: []ai.QueryFilter{{Field: "password_hash", Operator: "=", Value: "x"}},
	}); err == nil {
		t.Error("filtering on password_hash was accepted")
	}
	if _, err := q.RunSafeQuery(ctx, ai.QueryIntent{
		Entity:  "sessions",
		Filters: []ai.QueryFilter{{Field: "token_hash", Operator: "=", Value: "hash-1"}},
	}); err == nil {
		t.Error("filtering on token_hash was accepted")
	}
	// And as a group_by key.
	if _, err := q.RunSafeQuery(ctx, ai.QueryIntent{
		Entity: "users", Aggregate: "group_by", GroupBy: "password_hash",
	}); err == nil {
		t.Error("grouping by password_hash was accepted")
	}
}

func TestSafeQueryStore_FiltersAreBoundNotInterpolated(t *testing.T) {
	q, _, _ := newSeededQueryDB(t)
	ctx := context.Background()

	// Equality on a text column.
	got, err := q.RunSafeQuery(ctx, ai.QueryIntent{
		Entity:  "users",
		Filters: []ai.QueryFilter{{Field: "email", Operator: "=", Value: "raymondproguy@dev.com"}},
	})
	if err != nil {
		t.Fatalf("= filter: %v", err)
	}
	if len(got.Rows) != 1 || got.Rows[0][1] != "raymondproguy@dev.com" {
		t.Errorf("= filter returned %v", got.Rows)
	}

	// > and < against an INTEGER column, with the value bound as text —
	// SQLite's column affinity converts it, so this is not a string
	// comparison that would put "10" before "4".
	if got, err = q.RunSafeQuery(ctx, ai.QueryIntent{
		Entity:  "users",
		Filters: []ai.QueryFilter{{Field: "failed_attempts", Operator: ">", Value: "2"}},
	}); err != nil || len(got.Rows) != 1 || got.Rows[0][0] != "user-2" {
		t.Errorf("> filter returned %v, %v; want just user-2", got.Rows, err)
	}
	if got, err = q.RunSafeQuery(ctx, ai.QueryIntent{
		Entity:  "users",
		Filters: []ai.QueryFilter{{Field: "failed_attempts", Operator: "<", Value: "1"}},
	}); err != nil || len(got.Rows) != 1 || got.Rows[0][0] != "user-1" {
		t.Errorf("< filter returned %v, %v; want just user-1", got.Rows, err)
	}

	// Two filters AND together.
	if got, err = q.RunSafeQuery(ctx, ai.QueryIntent{
		Entity: "sessions",
		Filters: []ai.QueryFilter{
			{Field: "user_id", Operator: "=", Value: "user-1"},
			{Field: "ip", Operator: "=", Value: "10.0.0.2"},
		},
	}); err != nil || len(got.Rows) != 1 || got.Rows[0][0] != "sess-2" {
		t.Errorf("two filters returned %v, %v; want just sess-2", got.Rows, err)
	}

	// A value that would be catastrophic interpolated and inert bound.
	// The row simply does not match; no error, no dropped table.
	if got, err = q.RunSafeQuery(ctx, ai.QueryIntent{
		Entity:  "users",
		Filters: []ai.QueryFilter{{Field: "email", Operator: "=", Value: "' OR 1=1; DROP TABLE users; --"}},
	}); err != nil || len(got.Rows) != 0 {
		t.Errorf("injection-shaped value returned %v, %v; want no rows and no error", got.Rows, err)
	}
	var stillThere int
	if err := q.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&stillThere); err != nil || stillThere != 3 {
		t.Fatalf("users table has %d rows after the injection attempt (err %v); want 3", stillThere, err)
	}
}

// "contains" is the one operator whose value is rewritten rather than
// passed through — it becomes a LIKE with wildcards added by the store,
// so a model can never smuggle its own wildcards past the allowlist by
// spelling them in the value.
func TestSafeQueryStore_ContainsIsAWrappedLike(t *testing.T) {
	q, _, _ := newSeededQueryDB(t)
	ctx := context.Background()

	got, err := q.RunSafeQuery(ctx, ai.QueryIntent{
		Entity:  "users",
		Filters: []ai.QueryFilter{{Field: "email", Operator: "contains", Value: "raymond"}},
	})
	if err != nil {
		t.Fatalf("contains: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Errorf("contains raymond matched %d rows, want 2", len(got.Rows))
	}

	// SQLite's LIKE folds ASCII case, which is what makes this the honest
	// stand-in for Postgres's ILIKE over emails, IPs and event types.
	if got, err = q.RunSafeQuery(ctx, ai.QueryIntent{
		Entity:  "users",
		Filters: []ai.QueryFilter{{Field: "email", Operator: "contains", Value: "RAYMOND"}},
	}); err != nil || len(got.Rows) != 2 {
		t.Errorf("contains RAYMOND matched %d rows (err %v), want the same 2", len(got.Rows), err)
	}

	if got, err = q.RunSafeQuery(ctx, ai.QueryIntent{
		Entity:  "users",
		Filters: []ai.QueryFilter{{Field: "email", Operator: "contains", Value: "nobody"}},
	}); err != nil || len(got.Rows) != 0 {
		t.Errorf("contains nobody matched %v (err %v), want nothing", got.Rows, err)
	}
}

func TestSafeQueryStore_LimitCapsAndDefaults(t *testing.T) {
	q, _, _ := newSeededQueryDB(t)
	ctx := context.Background()

	got, err := q.RunSafeQuery(ctx, ai.QueryIntent{Entity: "users", Limit: 2})
	if err != nil {
		t.Fatalf("limit 2: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Errorf("limit 2 returned %d rows", len(got.Rows))
	}

	// Zero means the package default, not "no limit" — a missing LIMIT is
	// how an admin query accidentally pulls a whole users table.
	if got, err = q.RunSafeQuery(ctx, ai.QueryIntent{Entity: "users", Limit: 0}); err != nil || len(got.Rows) != 3 {
		t.Errorf("limit 0 returned %d rows (err %v); want all 3, under the default of %d", len(got.Rows), err, ai.DefaultLimit)
	}
}

func TestSafeQueryStore_CountAndGroupBy(t *testing.T) {
	q, _, _ := newSeededQueryDB(t)
	ctx := context.Background()

	got, err := q.RunSafeQuery(ctx, ai.QueryIntent{Entity: "sessions", Aggregate: "count"})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if len(got.Columns) != 1 || got.Columns[0] != "count" {
		t.Errorf("count columns = %v", got.Columns)
	}
	if len(got.Rows) != 1 || got.Rows[0][0] != "3" {
		t.Errorf("count = %v, want one row reading 3", got.Rows)
	}

	// A filtered count still counts, and is not silently limited.
	if got, err = q.RunSafeQuery(ctx, ai.QueryIntent{
		Entity:    "sessions",
		Aggregate: "count",
		Filters:   []ai.QueryFilter{{Field: "ip", Operator: "=", Value: "10.0.0.1"}},
		Limit:     1,
	}); err != nil || got.Rows[0][0] != "2" {
		t.Errorf("filtered count = %v, %v; want 2", got.Rows, err)
	}

	// group_by is ordered by count descending, so the busiest bucket is
	// first — the ordering an admin question ("which IPs are failing?")
	// actually wants.
	got, err = q.RunSafeQuery(ctx, ai.QueryIntent{
		Entity: "audit_events", Aggregate: "group_by", GroupBy: "type",
	})
	if err != nil {
		t.Fatalf("group_by: %v", err)
	}
	if len(got.Columns) != 2 || got.Columns[0] != "type" || got.Columns[1] != "count" {
		t.Errorf("group_by columns = %v", got.Columns)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("group_by returned %d buckets, want 2: %v", len(got.Rows), got.Rows)
	}
	if got.Rows[0][0] != string(store.EventLoginFailed) || got.Rows[0][1] != "3" {
		t.Errorf("busiest bucket = %v, want 3 login_failed", got.Rows[0])
	}
	if got.Rows[1][0] != string(store.EventLoginSuccess) || got.Rows[1][1] != "1" {
		t.Errorf("second bucket = %v, want 1 login_success", got.Rows[1])
	}
}

// A NULL groups as its own bucket and must scan, not error: audit_events
// and login_attempts both keep NULL user_id rows on purpose (a failure
// against an address with no account, or an event that outlived its
// user), so grouping by user_id meets them immediately.
func TestSafeQueryStore_GroupByToleratesNullKeys(t *testing.T) {
	q, _, _ := newSeededQueryDB(t)

	got, err := q.RunSafeQuery(context.Background(), ai.QueryIntent{
		Entity: "audit_events", Aggregate: "group_by", GroupBy: "user_id",
	})
	if err != nil {
		t.Fatalf("group_by user_id: %v", err)
	}
	if len(got.Rows) != 3 {
		t.Fatalf("got %d buckets, want 3 (user-1, user-2, NULL): %v", len(got.Rows), got.Rows)
	}
	var sawEmptyKey bool
	for _, row := range got.Rows {
		if row[0] == "" {
			sawEmptyKey = true
			if row[1] != "1" {
				t.Errorf("the NULL bucket holds %s rows, want 1", row[1])
			}
		}
	}
	if !sawEmptyKey {
		t.Errorf("no NULL bucket came back: %v", got.Rows)
	}
}

// Every allowlist branch, failing closed. RunSafeQuery re-checks rather
// than trusting ai.ExecuteQuery to have checked, which is exactly why
// each of these has to be asserted here and not only in ai's own tests.
func TestSafeQueryStore_RejectsEverythingOffTheAllowlist(t *testing.T) {
	q, _, _ := newSeededQueryDB(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name   string
		intent ai.QueryIntent
	}{
		{"unknown entity", ai.QueryIntent{Entity: "totp_secrets"}},
		{"empty entity", ai.QueryIntent{Entity: ""}},
		{"injection as entity", ai.QueryIntent{Entity: "users; DROP TABLE users"}},
		{"field from another entity", ai.QueryIntent{
			Entity:  "users",
			Filters: []ai.QueryFilter{{Field: "user_agent", Operator: "=", Value: "Firefox"}},
		}},
		{"unknown field", ai.QueryIntent{
			Entity:  "users",
			Filters: []ai.QueryFilter{{Field: "nope", Operator: "=", Value: "x"}},
		}},
		{"injection as field", ai.QueryIntent{
			Entity:  "users",
			Filters: []ai.QueryFilter{{Field: "email = '' OR 1=1 --", Operator: "=", Value: "x"}},
		}},
		{"unknown operator", ai.QueryIntent{
			Entity:  "users",
			Filters: []ai.QueryFilter{{Field: "email", Operator: "!=", Value: "x"}},
		}},
		{"injection as operator", ai.QueryIntent{
			Entity:  "users",
			Filters: []ai.QueryFilter{{Field: "email", Operator: "= '' OR 1=1 --", Value: "x"}},
		}},
		{"group_by field from another entity", ai.QueryIntent{
			Entity: "users", Aggregate: "group_by", GroupBy: "ip",
		}},
		{"group_by with no field", ai.QueryIntent{
			Entity: "users", Aggregate: "group_by", GroupBy: "",
		}},
	} {
		if _, err := q.RunSafeQuery(ctx, tc.intent); err == nil {
			t.Errorf("%s: accepted, want an error", tc.name)
		}
	}

	// Nothing above touched the data.
	var users int
	if err := q.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&users); err != nil || users != 3 {
		t.Errorf("users = %d (err %v) after the rejected intents; want 3", users, err)
	}
}

// The allowlist is defense-in-depth; this is the boundary underneath it.
// A read-only handle cannot write however wrong the layers above get,
// which is the whole reason the store's doc insists on mode=ro.
func TestSafeQueryStore_ReadOnlyHandleCannotWrite(t *testing.T) {
	_, _, path := newSeededQueryDB(t)
	ctx := context.Background()

	ro, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatalf("open read-only: %v", err)
	}
	defer ro.Close()

	q := NewSafeQueryStore(ro)
	got, err := q.RunSafeQuery(ctx, ai.QueryIntent{Entity: "users"})
	if err != nil {
		t.Fatalf("reading through a read-only handle: %v", err)
	}
	if len(got.Rows) != 3 {
		t.Errorf("read-only handle returned %d rows, want 3", len(got.Rows))
	}

	for _, stmt := range []string{
		`DELETE FROM users`,
		`UPDATE users SET email = 'attacker@dev.com'`,
		`DROP TABLE sessions`,
	} {
		if _, err := ro.ExecContext(ctx, stmt); err == nil {
			t.Errorf("%q succeeded on a mode=ro handle", stmt)
		}
	}
}

// Timestamps come back as this package's fixed-width TEXT rather than
// Postgres's rendering. Both parse as RFC 3339; the difference is real
// and documented, so it is asserted rather than left to be discovered
// by whoever first diffs two backends' output.
func TestSafeQueryStore_TimestampsComeBackInThePackageFormat(t *testing.T) {
	q, _, _ := newSeededQueryDB(t)

	got, err := q.RunSafeQuery(context.Background(), ai.QueryIntent{Entity: "users", Limit: 1})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	var createdAt int
	for i, c := range got.Columns {
		if c == "created_at" {
			createdAt = i
		}
	}
	raw := got.Rows[0][createdAt]
	if len(raw) != 30 {
		t.Errorf("created_at = %q (%d chars), want a fixed 30", raw, len(raw))
	}
	if _, err := time.Parse(time.RFC3339Nano, raw); err != nil {
		t.Errorf("created_at %q does not parse as RFC 3339: %v", raw, err)
	}
}
