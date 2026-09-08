package ai

import "context"

// ExecuteQuery turns natural language into a validated, read-only
// result set. naturalLanguage never reaches db directly — it only
// ever reaches provider, whose output (a QueryIntent) is validated
// against the allowlist before db.RunSafeQuery is called at all. If
// validation fails, RunSafeQuery is never invoked.
func ExecuteQuery(ctx context.Context, db QueryableStore, provider LLMProvider, naturalLanguage string) (QueryResult, error) {
	intent, err := provider.ParseQueryIntent(ctx, naturalLanguage)
	if err != nil {
		return QueryResult{}, err
	}
	return ExecuteIntent(ctx, db, intent)
}

// ExecuteIntent runs an already-built QueryIntent through the same
// default-limit-then-validate-then-execute path ExecuteQuery uses
// internally. It exists for a caller that needs to inspect or modify
// an intent between parsing it and running it — see package widget's
// Ask, which must force an identity-scoping filter onto whatever a
// model produced before any query reaches the store. There is no way
// to reach db.RunSafeQuery through this function without validateIntent
// running first; the safety gate is unconditional regardless of how
// intent was constructed.
func ExecuteIntent(ctx context.Context, db QueryableStore, intent QueryIntent) (QueryResult, error) {
	if intent.Limit == 0 {
		intent.Limit = DefaultLimit
	}

	if err := validateIntent(intent); err != nil {
		return QueryResult{}, err
	}

	return db.RunSafeQuery(ctx, intent)
}
