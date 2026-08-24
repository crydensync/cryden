// Package ai holds the pure, reusable logic behind csax's AI-assisted
// admin features. It never talks to an LLM provider or a database
// itself — it defines the shapes and the validation that make it safe
// for something else to do so. csax owns the actual CLI commands,
// prompts, and provider wiring; this package exists so that logic is
// testable without any of that.
//
// The one rule everything here exists to enforce: an LLM's output is
// untrusted data to validate, never code to execute. Nothing in this
// package lets a model produce a raw query string that reaches a
// database — only a strictly-typed, allowlisted QueryIntent that gets
// checked before it's ever turned into a real query.
package ai

import "context"

// LLMProvider translates natural language into a QueryIntent. Ships
// zero implementations here — the consumer (csax) brings its own
// provider and API key, the same pattern as notify.EmailSender and
// logger.Logger. This package never makes an outbound call to any AI
// provider itself.
type LLMProvider interface {
	ParseQueryIntent(ctx context.Context, naturalLanguage string) (QueryIntent, error)
}

// QueryIntent is a strictly-typed, allowlisted representation of a
// natural-language admin query. Every field is checked against an
// allowlist in validateIntent before ExecuteQuery ever builds a real
// query from it — a hallucinating or adversarially-prompted model can
// produce an intent that fails validation, but can never produce
// arbitrary executable SQL.
type QueryIntent struct {
	// Entity is the thing being queried. Must be one of AllowedEntities.
	Entity string
	// Filters narrow the result set. Every Field and Operator must be
	// allowlisted for Entity (see AllowedFields, AllowedOperators).
	Filters []QueryFilter
	// Aggregate is "", "count", or "group_by".
	Aggregate string
	// GroupBy is the column to group by when Aggregate == "group_by".
	// Must be an allowlisted field for Entity.
	GroupBy string
	// Limit caps the number of rows returned. Zero means the caller's
	// default applies (see DefaultLimit / MaxLimit in validate.go).
	Limit int
}

// QueryFilter is one condition within a QueryIntent.
type QueryFilter struct {
	Field    string
	Operator string
	Value    string
}

// QueryResult is what a validated QueryIntent resolves to.
type QueryResult struct {
	Columns []string
	Rows    [][]string
}

// QueryableStore executes an already-validated QueryIntent. The only
// production implementation (store/postgres) MUST use a read-only
// Postgres role for this connection — that's a real credential-level
// guarantee, not just a promise made in code, so a bug in validation
// still can't cause a write.
type QueryableStore interface {
	RunSafeQuery(ctx context.Context, intent QueryIntent) (QueryResult, error)
}
