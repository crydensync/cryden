package notify

import (
	"context"
	"time"
)

// WebhookEvent is one thing that happened, handed to a WebhookSender as
// it is written to the audit log.
//
// The fields are the audit event's own, deliberately — this is not a
// second, parallel event model with its own vocabulary to keep in sync.
// Type carries the string form of the store.AuditEventType that was
// recorded ("account_locked", "password_changed"), so a host can switch
// on it directly, and Metadata is that event's metadata unchanged, whose
// keys are documented per event type on the constants themselves.
type WebhookEvent struct {
	// ID identifies this occurrence, for a receiver that has to be
	// idempotent — at-least-once delivery is the only kind a queue can
	// promise, and a host retrying from its own queue will present the
	// same ID again.
	//
	// It is NOT the audit row's ID. The stores assign those themselves
	// and do not report them back, so there is nothing here to match
	// against; correlate on Type plus UserID plus OccurredAt if you need
	// to find the row.
	ID string

	// Type is the recorded store.AuditEventType, as a string so that
	// implementing this interface requires no import from the engine's
	// internals.
	Type string

	// UserID is whose account the event concerns. Empty for the events
	// that genuinely have no user behind them — a failed login naming an
	// email nobody registered, for one.
	UserID string

	// IP is the address the triggering request came from, as the caller
	// reported it. Empty where the operation had no request behind it.
	IP string

	// Metadata is the event's own metadata, or nil where it had none.
	// A fresh copy: mutating it cannot reach the audit record.
	Metadata map[string]string

	// OccurredAt is when the engine recorded the event, in UTC. Stamped
	// by the engine rather than read back from the store, which assigns
	// its own timestamp and does not return it.
	OccurredAt time.Time
}

// WebhookSender delivers engine events to the host app. Like
// EmailSender and Logger, this is an interface only — the engine ships
// no implementation, makes no outbound HTTP call itself, and knows
// nothing about your endpoint, your signing scheme or your retry
// policy. It surfaces the event; what happens to it is entirely the
// host's.
//
// Two things about how it is called shape any implementation worth
// deploying:
//
//  1. SendWebhook runs SYNCHRONOUSLY on the request path, in the same
//     goroutine as the login (or signup, or revocation) that triggered
//     it, immediately after the audit row is written. Whatever it costs
//     is added to that operation's latency. The implementation a
//     production host wants is therefore an enqueue — push the event
//     onto a queue, a channel, a jobs table — and let something else
//     make the HTTP call, sign it, retry it and back off. An
//     http.Client.Do in here is a third party's downtime becoming your
//     login latency.
//
//  2. An error NEVER fails the operation. It is logged, at Error level,
//     and the login the host was to be told about succeeds regardless —
//     the same fire-and-forget contract the audit write above it has.
//     A webhook is a notification, not a gate; nothing in the engine
//     waits for the host to agree.
//
// ctx is the triggering request's context, so it may already be
// cancelled by the time a slow sender gets to use it. One more reason
// for the enqueue: a queue write that ignores a cancelled ctx still
// delivers the event, while an HTTP call inheriting it silently does
// not.
type WebhookSender interface {
	SendWebhook(ctx context.Context, event WebhookEvent) error
}
