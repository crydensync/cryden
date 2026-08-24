package ai

import (
	"errors"
	"fmt"
)

// ErrUnsafeQueryIntent is returned when a QueryIntent fails allowlist
// validation. Deliberately generic — never echoes back the specific
// bad value in a way a caller might be tempted to surface directly to
// an end user or reuse to build a query some other way.
var ErrUnsafeQueryIntent = errors.New("ai: query intent failed allowlist validation")

// DefaultLimit and MaxLimit bound how much a single AI-driven query
// can return, regardless of what the model or the caller asked for.
const (
	DefaultLimit = 50
	MaxLimit     = 500
)

// AllowedEntities are the only tables an AI-driven query may touch.
var AllowedEntities = map[string]bool{
	"users":        true,
	"sessions":     true,
	"audit_events": true,
}

// AllowedOperators are the only comparison operators a filter may use.
var AllowedOperators = map[string]bool{
	"=":        true,
	">":        true,
	"<":        true,
	"contains": true,
}

// AllowedFields lists, per entity, the columns an AI-driven query may
// filter, group by, or return. PasswordHash and TokenHash are
// deliberately absent from every list below — those must never be
// queryable or returnable through this path, allowlist violation or
// not.
var AllowedFields = map[string]map[string]bool{
	"users": {
		"id":              true,
		"email":           true,
		"failed_attempts": true,
		"locked_until":    true,
		"created_at":      true,
	},
	"sessions": {
		"id":         true,
		"user_id":    true,
		"ip":         true,
		"user_agent": true,
		"created_at": true,
		"revoked_at": true,
	},
	"audit_events": {
		"id":         true,
		"type":       true,
		"user_id":    true,
		"ip":         true,
		"created_at": true,
	},
}

// EntityColumns gives a deterministic, ordered column list per
// entity — the same set as AllowedFields, just ordered, since a Go
// map has no defined iteration order and RunSafeQuery needs to build
// a stable SELECT column list. Keep these two in sync; a test asserts
// they match.
var EntityColumns = map[string][]string{
	"users":        {"id", "email", "failed_attempts", "locked_until", "created_at"},
	"sessions":     {"id", "user_id", "ip", "user_agent", "created_at", "revoked_at"},
	"audit_events": {"id", "type", "user_id", "ip", "created_at"},
}

var allowedAggregates = map[string]bool{
	"":         true,
	"count":    true,
	"group_by": true,
}

// validateIntent is the safety gate: every field of intent must be
// allowlisted before ExecuteQuery is permitted to build a real query
// from it. Fails closed — anything not explicitly recognized is
// rejected, not passed through.
func validateIntent(intent QueryIntent) error {
	if !AllowedEntities[intent.Entity] {
		return fmt.Errorf("%w: entity %q not allowed", ErrUnsafeQueryIntent, intent.Entity)
	}
	fields := AllowedFields[intent.Entity]

	if !allowedAggregates[intent.Aggregate] {
		return fmt.Errorf("%w: aggregate %q not allowed", ErrUnsafeQueryIntent, intent.Aggregate)
	}

	if intent.Aggregate == "group_by" {
		if intent.GroupBy == "" || !fields[intent.GroupBy] {
			return fmt.Errorf("%w: group_by field %q not allowed for entity %q", ErrUnsafeQueryIntent, intent.GroupBy, intent.Entity)
		}
	}

	for _, f := range intent.Filters {
		if !fields[f.Field] {
			return fmt.Errorf("%w: filter field %q not allowed for entity %q", ErrUnsafeQueryIntent, f.Field, intent.Entity)
		}
		if !AllowedOperators[f.Operator] {
			return fmt.Errorf("%w: operator %q not allowed", ErrUnsafeQueryIntent, f.Operator)
		}
	}

	if intent.Limit < 0 || intent.Limit > MaxLimit {
		return fmt.Errorf("%w: limit %d out of range (max %d)", ErrUnsafeQueryIntent, intent.Limit, MaxLimit)
	}

	return nil
}
