package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/crydensync/cryden/v2/ai"
)

// operatorSQL maps ai's allowlisted operators to real SQL. Anything not
// in this map is a bug upstream — ExecuteQuery must never call
// RunSafeQuery with an intent that didn't pass validateIntent first.
//
// "contains" is LIKE, not ILIKE: SQLite has no ILIKE, and does not need
// one here, because its LIKE is already case-insensitive for ASCII. The
// fields this can reach are emails, IPs and event types, so ASCII is
// the whole range in practice — but the difference is real for
// non-ASCII input, where Postgres's ILIKE folds case and SQLite's LIKE
// does not without the ICU extension loaded.
var operatorSQL = map[string]string{
	"=":        "=",
	">":        ">",
	"<":        "<",
	"contains": "LIKE",
}

// SafeQueryStore is the SQLite ai.QueryableStore implementation for the
// AI-assisted admin features.
//
// The db passed to NewSafeQueryStore MUST be opened read-only. In
// store/postgres that means a read-only role; here it means opening the
// same file a second time with mode=ro in the DSN — for example
// "file:cryden.db?mode=ro" — and handing that *sql.DB to this store and
// nothing else. That is the actual safety boundary: even a bug in
// ai.validateIntent, or in the query-building below, cannot cause a
// write if the handle itself is physically incapable of one. Allowlist
// validation is defense-in-depth on top of that, not a substitute.
//
// mode=ro and not query_only: the pragma is per-connection, and
// *sql.DB is a pool that opens new connections whenever it feels like
// it, so a pragma set on one connection says nothing about the next.
// A read-only handle applies to every connection the pool ever makes.
type SafeQueryStore struct {
	db *sql.DB
}

// NewSafeQueryStore wraps an existing read-only *sql.DB. The caller
// owns the connection's lifecycle, same as every other constructor in
// this package.
func NewSafeQueryStore(db *sql.DB) *SafeQueryStore {
	return &SafeQueryStore{db: db}
}

// RunSafeQuery builds and executes a parameterized query from an
// already-validated QueryIntent. It never accepts free-form SQL and
// never string-formats a filter's Value into the query — every value
// goes through a placeholder, same as every other store here.
//
// Membership is re-checked against ai's allowlists even though
// ai.ExecuteQuery has already done it, which is what makes this store
// safe to call directly in tests without going through ExecuteQuery.
//
// One behavioural difference from Postgres worth knowing before you
// compare outputs: timestamp columns come back in this package's TEXT
// format (see the package doc), not Postgres's. Both are RFC 3339; the
// SQLite one is zero-padded to a fixed width.
func (s *SafeQueryStore) RunSafeQuery(ctx context.Context, intent ai.QueryIntent) (ai.QueryResult, error) {
	if !ai.AllowedEntities[intent.Entity] {
		return ai.QueryResult{}, fmt.Errorf("sqlite: entity %q not allowed", intent.Entity)
	}
	cols := ai.EntityColumns[intent.Entity]

	where, args, err := buildWhereClause(intent)
	if err != nil {
		return ai.QueryResult{}, err
	}

	limit := intent.Limit
	if limit <= 0 {
		limit = ai.DefaultLimit
	}

	switch intent.Aggregate {
	case "count":
		return s.runCount(ctx, intent.Entity, where, args)
	case "group_by":
		return s.runGroupBy(ctx, intent.Entity, intent.GroupBy, where, args)
	default:
		return s.runSelect(ctx, intent.Entity, cols, where, args, limit)
	}
}

func (s *SafeQueryStore) runSelect(ctx context.Context, entity string, cols []string, where string, args []any, limit int) (ai.QueryResult, error) {
	query := fmt.Sprintf("SELECT %s FROM %s%s LIMIT ?", strings.Join(cols, ", "), entity, where)
	rows, err := s.db.QueryContext(ctx, query, append(args, limit)...)
	if err != nil {
		return ai.QueryResult{}, err
	}
	defer rows.Close()

	result := ai.QueryResult{Columns: cols}
	dest := make([]sql.NullString, len(cols))
	scanArgs := make([]any, len(cols))
	for i := range dest {
		scanArgs[i] = &dest[i]
	}
	for rows.Next() {
		if err := rows.Scan(scanArgs...); err != nil {
			return ai.QueryResult{}, err
		}
		row := make([]string, len(cols))
		for i, v := range dest {
			row[i] = v.String
		}
		result.Rows = append(result.Rows, row)
	}
	return result, rows.Err()
}

func (s *SafeQueryStore) runCount(ctx context.Context, entity, where string, args []any) (ai.QueryResult, error) {
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s%s", entity, where)
	var count int64
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return ai.QueryResult{}, err
	}
	return ai.QueryResult{Columns: []string{"count"}, Rows: [][]string{{fmt.Sprintf("%d", count)}}}, nil
}

func (s *SafeQueryStore) runGroupBy(ctx context.Context, entity, groupBy, where string, args []any) (ai.QueryResult, error) {
	if !ai.AllowedFields[entity][groupBy] {
		return ai.QueryResult{}, fmt.Errorf("sqlite: group_by field %q not allowed for entity %q", groupBy, entity)
	}
	query := fmt.Sprintf("SELECT %s, COUNT(*) FROM %s%s GROUP BY %s ORDER BY COUNT(*) DESC", groupBy, entity, where, groupBy)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return ai.QueryResult{}, err
	}
	defer rows.Close()

	result := ai.QueryResult{Columns: []string{groupBy, "count"}}
	for rows.Next() {
		var key sql.NullString
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			return ai.QueryResult{}, err
		}
		result.Rows = append(result.Rows, []string{key.String, fmt.Sprintf("%d", count)})
	}
	return result, rows.Err()
}

// buildWhereClause builds a parameterized WHERE clause. Every value is
// bound as a placeholder, never interpolated into the query string —
// the only things string-formatted into the SQL itself are the field
// name and the operator, both re-checked against the allowlist
// immediately below rather than trusted from the caller.
func buildWhereClause(intent ai.QueryIntent) (string, []any, error) {
	if len(intent.Filters) == 0 {
		return "", nil, nil
	}
	fields := ai.AllowedFields[intent.Entity]

	var clauses []string
	var args []any
	for _, f := range intent.Filters {
		if !fields[f.Field] {
			return "", nil, fmt.Errorf("sqlite: filter field %q not allowed for entity %q", f.Field, intent.Entity)
		}
		op, ok := operatorSQL[f.Operator]
		if !ok {
			return "", nil, fmt.Errorf("sqlite: operator %q not allowed", f.Operator)
		}
		args = append(args, valueForOperator(f.Operator, f.Value))
		clauses = append(clauses, fmt.Sprintf("%s %s ?", f.Field, op))
	}
	return " WHERE " + strings.Join(clauses, " AND "), args, nil
}

func valueForOperator(operator, value string) string {
	if operator == "contains" {
		return "%" + value + "%"
	}
	return value
}

var _ ai.QueryableStore = (*SafeQueryStore)(nil)
