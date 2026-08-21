package ai

import (
	"context"
	"errors"
	"testing"
)

// fakeLLMProvider returns a fixed QueryIntent — no real model call,
// matching the design's "no real API key needed for this layer of
// testing" plan.
type fakeLLMProvider struct {
	intent QueryIntent
	err    error
}

func (f fakeLLMProvider) ParseQueryIntent(ctx context.Context, naturalLanguage string) (QueryIntent, error) {
	return f.intent, f.err
}

// fakeQueryableStore records whether RunSafeQuery was ever called, so
// tests can assert an unsafe intent never reaches it.
type fakeQueryableStore struct {
	called      bool
	lastIntent  QueryIntent
	returnValue QueryResult
	returnErr   error
}

func (f *fakeQueryableStore) RunSafeQuery(ctx context.Context, intent QueryIntent) (QueryResult, error) {
	f.called = true
	f.lastIntent = intent
	return f.returnValue, f.returnErr
}

func TestExecuteQuery_ValidIntentReachesStore(t *testing.T) {
	provider := fakeLLMProvider{intent: QueryIntent{
		Entity:  "users",
		Filters: []QueryFilter{{Field: "email", Operator: "contains", Value: "example.com"}},
	}}
	db := &fakeQueryableStore{returnValue: QueryResult{Columns: []string{"id", "email"}}}

	result, err := ExecuteQuery(context.Background(), db, provider, "show me users from example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !db.called {
		t.Error("expected RunSafeQuery to be called for a valid intent")
	}
	if len(result.Columns) != 2 {
		t.Errorf("expected result to pass through from the store, got %+v", result)
	}
	if db.lastIntent.Limit != DefaultLimit {
		t.Errorf("expected zero-limit intent to be defaulted to %d, got %d", DefaultLimit, db.lastIntent.Limit)
	}
}

func TestExecuteQuery_DisallowedEntityNeverReachesStore(t *testing.T) {
	// This is the actual security property: even if a model
	// hallucinates or is adversarially prompted into naming a table
	// outside the allowlist, RunSafeQuery must never be called.
	provider := fakeLLMProvider{intent: QueryIntent{Entity: "pg_shadow"}}
	db := &fakeQueryableStore{}

	_, err := ExecuteQuery(context.Background(), db, provider, "show me the password hashes")
	if !errors.Is(err, ErrUnsafeQueryIntent) {
		t.Fatalf("expected ErrUnsafeQueryIntent, got %v", err)
	}
	if db.called {
		t.Error("RunSafeQuery must not be called when the intent fails validation")
	}
}

func TestExecuteQuery_DisallowedFieldNeverReachesStore(t *testing.T) {
	provider := fakeLLMProvider{intent: QueryIntent{
		Entity:  "users",
		Filters: []QueryFilter{{Field: "password_hash", Operator: "=", Value: "x"}},
	}}
	db := &fakeQueryableStore{}

	_, err := ExecuteQuery(context.Background(), db, provider, "find users with this password hash")
	if !errors.Is(err, ErrUnsafeQueryIntent) {
		t.Fatalf("expected ErrUnsafeQueryIntent, got %v", err)
	}
	if db.called {
		t.Error("RunSafeQuery must not be called when a filter field isn't allowlisted")
	}
}

func TestExecuteQuery_DisallowedOperatorNeverReachesStore(t *testing.T) {
	provider := fakeLLMProvider{intent: QueryIntent{
		Entity:  "sessions",
		Filters: []QueryFilter{{Field: "ip", Operator: "DROP TABLE", Value: "x"}},
	}}
	db := &fakeQueryableStore{}

	_, err := ExecuteQuery(context.Background(), db, provider, "malicious input")
	if !errors.Is(err, ErrUnsafeQueryIntent) {
		t.Fatalf("expected ErrUnsafeQueryIntent, got %v", err)
	}
	if db.called {
		t.Error("RunSafeQuery must not be called when an operator isn't allowlisted")
	}
}

func TestExecuteQuery_GroupByMustBeAllowlistedField(t *testing.T) {
	provider := fakeLLMProvider{intent: QueryIntent{
		Entity:    "audit_events",
		Aggregate: "group_by",
		GroupBy:   "metadata", // not in AllowedFields["audit_events"]
	}}
	db := &fakeQueryableStore{}

	_, err := ExecuteQuery(context.Background(), db, provider, "group audit events by metadata")
	if !errors.Is(err, ErrUnsafeQueryIntent) {
		t.Fatalf("expected ErrUnsafeQueryIntent, got %v", err)
	}
	if db.called {
		t.Error("RunSafeQuery must not be called for an unallowlisted group_by field")
	}
}

func TestExecuteQuery_LimitOverMaxIsRejected(t *testing.T) {
	provider := fakeLLMProvider{intent: QueryIntent{Entity: "users", Limit: MaxLimit + 1}}
	db := &fakeQueryableStore{}

	_, err := ExecuteQuery(context.Background(), db, provider, "show me everyone")
	if !errors.Is(err, ErrUnsafeQueryIntent) {
		t.Fatalf("expected ErrUnsafeQueryIntent, got %v", err)
	}
	if db.called {
		t.Error("RunSafeQuery must not be called when the limit exceeds MaxLimit")
	}
}

func TestExecuteQuery_ProviderErrorNeverReachesStore(t *testing.T) {
	provider := fakeLLMProvider{err: errors.New("provider timeout")}
	db := &fakeQueryableStore{}

	_, err := ExecuteQuery(context.Background(), db, provider, "anything")
	if err == nil {
		t.Fatal("expected the provider's error to propagate")
	}
	if db.called {
		t.Error("RunSafeQuery must not be called if the provider itself failed")
	}
}
