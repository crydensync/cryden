// Package widget packages ai's admin-facing query surface for a
// different, much less trusted caller: a host application's own end
// users. See docs/design/ask-ai-widget.md for the full reasoning.
//
// The one rule this package exists to enforce: no QueryIntent —
// honestly parsed, hallucinated, or shaped by a successful prompt
// injection — ever reaches ai.QueryableStore without first being
// force-scoped to the one identity the host's own authentication
// supplied. That scoping runs in Go code, unconditionally, on every
// intent; it does not consult, trust, or partially honor whatever
// identity a model's output claims.
package widget

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/crydensync/cryden/v2/ai"
)

// ErrMissingOwner is returned when ownerUserID is empty. Ask has
// nothing to scope a query to without it, and — this being the whole
// point of the package — there is no fallback that queries without an
// owner instead.
var ErrMissingOwner = errors.New("widget: ownerUserID is required")

// ErrEntityNotAvailable is returned when a parsed QueryIntent names an
// entity scopeToOwner does not know how to bound to one identity. This
// is a fail-closed default: an entity ai/ allowlists tomorrow that this
// package hasn't been taught to scope yet is refused here, not passed
// through unscoped.
var ErrEntityNotAvailable = errors.New("widget: entity not available to end users")

// Composer turns a validated, already-scoped ai.QueryResult into the
// natural-language answer a host shows its end user. Ships zero
// implementations — same pattern as ai.LLMProvider: the host brings
// its own model call for this too. Composer sees only data Ask has
// already restricted to ownerUserID's own rows.
type Composer interface {
	ComposeAnswer(ctx context.Context, question string, result ai.QueryResult) (string, error)
}

// Config is what Ask needs. Provider and Store are required — the same
// ai.LLMProvider and ai.QueryableStore the admin-facing ai package
// already defines; this package adds no second query mechanism, only
// a mandatory scoping step in front of the existing one. Composer is
// optional: a nil Composer is a valid, strictly safer default, and Ask
// falls back to RenderResult, which involves no second model call at
// all.
type Config struct {
	Provider ai.LLMProvider
	Store    ai.QueryableStore
	Composer Composer
}

// Answer is what Ask returns: Result is the validated, owner-scoped
// data (for a host that wants the structured form), Text is either
// Composer's prose or, absent a Composer, RenderResult's deterministic
// rendering.
type Answer struct {
	Result ai.QueryResult
	Text   string
}

// Ask answers question on behalf of ownerUserID, an end user of a host
// application.
//
// ownerUserID MUST come from the host's own authentication of the
// current caller — a session, a JWT claim, whatever the host already
// uses to know who this request is from — and never from question or
// anything derived from it. There is no field on ai.QueryIntent for an
// identity and nothing here ever reads one out of the model's output;
// that is not an oversight, it is the design (see
// docs/design/ask-ai-widget.md).
//
// The path: cfg.Provider.ParseQueryIntent parses question exactly as
// ai.ExecuteQuery would, scopeToOwner then force-rewrites whatever
// identity-bearing filter the parsed intent carries — discarding it
// outright rather than validating it — to name ownerUserID, and only
// then does the result reach ai.ExecuteIntent, which runs the same
// allowlist validation ai.ExecuteQuery itself runs before ever calling
// cfg.Store.
func Ask(ctx context.Context, cfg Config, ownerUserID, question string) (Answer, error) {
	if ownerUserID == "" {
		return Answer{}, ErrMissingOwner
	}
	if cfg.Provider == nil {
		return Answer{}, fmt.Errorf("widget: Config.Provider is required")
	}
	if cfg.Store == nil {
		return Answer{}, fmt.Errorf("widget: Config.Store is required")
	}

	intent, err := cfg.Provider.ParseQueryIntent(ctx, question)
	if err != nil {
		return Answer{}, err
	}

	scoped, err := scopeToOwner(intent, ownerUserID)
	if err != nil {
		return Answer{}, err
	}

	result, err := ai.ExecuteIntent(ctx, cfg.Store, scoped)
	if err != nil {
		return Answer{}, err
	}

	text := RenderResult(result)
	if cfg.Composer != nil {
		composed, err := cfg.Composer.ComposeAnswer(ctx, question, result)
		if err != nil {
			return Answer{}, err
		}
		text = composed
	}

	return Answer{Result: result, Text: text}, nil
}

// scopeToOwner is the entire security boundary this package exists
// for. It does not read, validate, or partially trust any
// identity-bearing filter the model produced — it discards it outright
// and substitutes the one true value, the same way a row-level-security
// policy rewrites a query rather than negotiating with it. See
// docs/design/ask-ai-widget.md for why overwrite rather than
// validate-and-reject: a reject path still has to trust the filter
// enough to compare it, and turns "did you try someone else's data"
// into an oracle. Overwrite has no oracle — every phrasing of the
// question, honest or adversarial, produces the same executed query.
func scopeToOwner(intent ai.QueryIntent, ownerUserID string) (ai.QueryIntent, error) {
	switch intent.Entity {
	case "users":
		// The row itself IS the user — the only safe "users" query an
		// end user can make is about themself. Every filter the model
		// produced is dropped, not merged with.
		intent.Filters = []ai.QueryFilter{{Field: "id", Operator: "=", Value: ownerUserID}}
	case "sessions", "audit_events":
		// Strip any user_id filter the model produced — honest or
		// injected makes no difference — and force the real one.
		// Every other filter (ip, type, created_at, ...) is left
		// alone: none of them can cross the identity boundary once
		// user_id is forced.
		kept := intent.Filters[:0:0] // fresh backing array; never mutate the caller's slice
		for _, f := range intent.Filters {
			if f.Field != "user_id" {
				kept = append(kept, f)
			}
		}
		intent.Filters = append(kept, ai.QueryFilter{Field: "user_id", Operator: "=", Value: ownerUserID})
	default:
		return ai.QueryIntent{}, fmt.Errorf("%w: %q", ErrEntityNotAvailable, intent.Entity)
	}
	return intent, nil
}

// RenderResult is the default, no-second-model-call rendering of an
// ai.QueryResult: a plain-text table. Exported so a host without a
// Composer configured still gets a usable Answer.Text, and so a host
// that does supply one can still fall back to this — for a debug view,
// or while it's building its own Composer.
func RenderResult(result ai.QueryResult) string {
	if len(result.Rows) == 0 {
		return "No matching results."
	}
	var b strings.Builder
	b.WriteString(strings.Join(result.Columns, " | "))
	for _, row := range result.Rows {
		b.WriteString("\n")
		b.WriteString(strings.Join(row, " | "))
	}
	return b.String()
}
