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

	if intent.Limit == 0 {
		intent.Limit = DefaultLimit
	}

	if err := validateIntent(intent); err != nil {
		return QueryResult{}, err
	}

	return db.RunSafeQuery(ctx, intent)
}
