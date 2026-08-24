package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/lib/pq"

	"github.com/crydensync/cryden/v2/ai"
)

// operatorSQL maps ai's allowlisted operators to real SQL. Anything
// not in this map is a bug upstream — ExecuteQuery must never call
// RunSafeQuery with an intent that didn't pass validateIntent first.
var operatorSQL = map[string]string{
	"=":        "=",
	">":        ">",
	"<":        "<",
	"contains": "ILIKE",
}

// SafeQueryStore is the v1 production ai.QueryableStore
// implementation for csax's AI-assisted admin features.
//
// The db passed to NewSafeQueryStore MUST be opened with a read-only
// Postgres role. That is the actual safety boundary — even a bug in
// ai.validateIntent, or in the query-building below, cannot cause a
// write if the credential itself is physically incapable of one.
// Allowlist validation is defense-in-depth on top of that, not a
// substitute for it.
type SafeQueryStore struct {
	db *sql.DB
}

// NewSafeQueryStore wraps an existing *sql.DB opened with a read-only
// role. The caller owns the connection's lifecycle, same as every
// other store/postgres constructor.
func NewSafeQueryStore(db *sql.DB) *SafeQueryStore {
	return &SafeQueryStore{db: db}
}

// RunSafeQuery builds and executes a parameterized query from an
// already-validated QueryIntent. It never accepts free-form SQL and
// never string-formats a filter's Value into the query — every value
// goes through a placeholder ($1, $2, ...), same as every other store
// in this package.
//
// This function trusts that intent already passed ai's
// validateIntent (via ai.ExecuteQuery) — Entity, every Filter.Field,
// every Filter.Operator, and GroupBy are assumed allowlisted.
// Re-checking membership here anyway (rather than trusting the
// caller blindly) is what makes this store safe to call directly in
// tests without going through ExecuteQuery.
func (s *SafeQueryStore) RunSafeQuery(ctx context.Context, intent ai.QueryIntent) (ai.QueryResult, error) {
	if !ai.AllowedEntities[intent.Entity] {
		return ai.QueryResult{}, fmt.Errorf("postgres: entity %q not allowed", intent.Entity)
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
	query := fmt.Sprintf("SELECT %s FROM %s%s LIMIT $%d", strings.Join(cols, ", "), entity, where, len(args)+1)
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
		return ai.QueryResult{}, fmt.Errorf("postgres: group_by field %q not allowed for entity %q", groupBy, entity)
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

// buildWhereClause builds a parameterized WHERE clause. Every value
// is bound as a placeholder, never interpolated into the query
// string — the only thing that gets string-formatted into the SQL
// itself is the field name and operator, both of which are
// re-checked against the allowlist immediately below, not just
// trusted from the caller.
func buildWhereClause(intent ai.QueryIntent) (string, []any, error) {
	if len(intent.Filters) == 0 {
		return "", nil, nil
	}
	fields := ai.AllowedFields[intent.Entity]

	var clauses []string
	var args []any
	for _, f := range intent.Filters {
		if !fields[f.Field] {
			return "", nil, fmt.Errorf("postgres: filter field %q not allowed for entity %q", f.Field, intent.Entity)
		}
		op, ok := operatorSQL[f.Operator]
		if !ok {
			return "", nil, fmt.Errorf("postgres: operator %q not allowed", f.Operator)
		}
		args = append(args, valueForOperator(f.Operator, f.Value))
		clauses = append(clauses, fmt.Sprintf("%s %s $%d", f.Field, op, len(args)))
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
