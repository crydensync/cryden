package cryden

import (
	"context"
	"time"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/notify"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
)

// DefaultWebhookEvents is the set Config.WebhookEvents falls back to:
// the events a host app usually wants to act on, and only those.
//
// The filter exists because the engine records 31 kinds of event and
// most of them are nobody's business outside the audit table. Three in
// particular are absent on purpose, being the three a host is most
// likely to ask for and most likely to regret:
//
//   - store.EventLoginSuccess — every login, of every user, forever.
//   - store.EventTokenRotated — every refresh, so once per active
//     session per AccessTokenTTL. At the default fifteen minutes, a
//     thousand logged-in users is four thousand deliveries an hour.
//   - store.EventLoginFailed — volume chosen by whoever is attacking
//     you, which makes it a way to turn a password-guessing script into
//     load on your webhook endpoint.
//
// What is here is bounded by real human action instead: credentials and
// second factors changing, the account itself changing, and the four
// events that mean something has gone wrong. Deliberately no "all"
// switch anywhere in this feature — an "all" would silently start
// delivering every event type added to the engine after the host wrote
// their sender, including the next high-volume one.
//
// Returns a fresh slice, so appending to it is safe:
//
//	WebhookEvents: append(cryden.DefaultWebhookEvents(), store.EventLoginSuccess),
func DefaultWebhookEvents() []store.AuditEventType {
	return []store.AuditEventType{
		// The account exists, or stops existing.
		store.EventSignupSuccess,
		store.EventAccountDeleted,

		// Credentials and contact details changed — the classic
		// account-takeover sequence, and what "was this you?" email is for.
		store.EventPasswordChanged,
		store.EventEmailChanged,

		// A sign-in method was added or taken away. Removal matters more
		// than addition: turning MFA off is a step in taking an account,
		// not a preference.
		store.EventOAuthLinked,
		store.EventTOTPEnabled,
		store.EventTOTPDisabled,
		store.EventWebAuthnRegistered,
		store.EventWebAuthnRemoved,
		store.EventRecoveryCodesGenerated,
		store.EventAPIKeyCreated,
		store.EventAPIKeyRevoked,

		// Something is wrong. All four are already rare by construction,
		// and all four are the reason a host wants webhooks at all.
		store.EventAccountLocked,
		store.EventTokenReuseDetected,
		store.EventAnomalyDetected,
		store.EventCredentialStuffingDetected,
	}
}

// webhookRecorder decorates the host's store.AuditStore, dispatching a
// webhook for the subscribed events as they are recorded.
//
// This is the whole wiring, and it is a decorator rather than a new
// parameter on the 33 audit.Record call sites for one reason beyond the
// diff: those sites are the definition of "an event happened here". A
// second mechanism alongside them would be a second thing to remember
// at every future call site, and the failure mode of forgetting is an
// event that is audited but never delivered — silent, and only ever
// noticed by the host who needed it. Wrapped here, an event that
// reaches the audit log reaches the filter, and nothing in auth/ knows
// this type exists: every call site holds store.AuditStore.
//
// Reads (ListByUser, SearchByType) are the embedded store's, untouched.
type webhookRecorder struct {
	store.AuditStore

	sender notify.WebhookSender
	events map[store.AuditEventType]struct{}
	ids    security.IDGenerator
	log    logger.Logger
}

// newWebhookRecorder wraps audit. Only ever called with a non-nil
// sender — New leaves Config.Audit undecorated when Config.Webhooks is
// nil, so a host not using this feature runs the code path it ran
// before it existed.
func newWebhookRecorder(audit store.AuditStore, sender notify.WebhookSender, events []store.AuditEventType, ids security.IDGenerator, log logger.Logger) *webhookRecorder {
	subscribed := make(map[store.AuditEventType]struct{}, len(events))
	for _, t := range events {
		subscribed[t] = struct{}{}
	}
	return &webhookRecorder{
		AuditStore: audit,
		sender:     sender,
		events:     subscribed,
		ids:        ids,
		log:        log,
	}
}

// Record writes the audit row first, then notifies. That order is
// deliberate: the row is the system of record, a host reacting to a
// webhook by reading the audit log finds the event already there, and a
// process dying between the two loses the notification rather than the
// evidence.
//
// A failed audit write does not cancel the notification. The event
// happened either way, and a host told about a lockout it cannot find a
// row for is better served than a host told nothing because the
// database was briefly unreachable. The store's error is returned
// unchanged; the caller's existing handling of it — log it, never fail
// the operation — is untouched.
func (r *webhookRecorder) Record(ctx context.Context, event store.AuditEvent) error {
	err := r.AuditStore.Record(ctx, event)

	if _, subscribed := r.events[event.Type]; !subscribed {
		return err
	}

	log := logger.ForContext(ctx, r.log)

	// An ID generator failing means crypto/rand failed, at which point
	// the delivery is worth more than its idempotency key: the event
	// goes out with an empty ID and the failure is logged, rather than
	// the host hearing nothing about an account lockout because a UUID
	// could not be made.
	id, idErr := r.ids.New()
	if idErr != nil {
		log.Error("webhook: event id generation failed", map[string]string{
			"error": idErr.Error(),
			"type":  string(event.Type),
		})
	}

	// Copied so that a sender holding onto the map, or editing it, cannot
	// reach the audit record — the in-memory store keeps the same map by
	// reference, and this is cheap insurance against a bug that would
	// otherwise surface as corrupted audit history.
	var metadata map[string]string
	if event.Metadata != nil {
		metadata = make(map[string]string, len(event.Metadata))
		for k, v := range event.Metadata {
			metadata[k] = v
		}
	}

	if sendErr := r.sender.SendWebhook(ctx, notify.WebhookEvent{
		ID:         id,
		Type:       string(event.Type),
		UserID:     event.UserID,
		IP:         event.IP,
		Metadata:   metadata,
		OccurredAt: time.Now().UTC(),
	}); sendErr != nil {
		// Logged and dropped, exactly like the audit write above it. The
		// operation that triggered this has already happened and is not
		// being undone because the host's queue is full.
		log.Error("webhook: send failed", map[string]string{
			"error":    sendErr.Error(),
			"type":     string(event.Type),
			"user_id":  event.UserID,
			"event_id": id,
		})
		return err
	}

	log.Debug("webhook: event sent", map[string]string{
		"type":     string(event.Type),
		"user_id":  event.UserID,
		"event_id": id,
	})
	return err
}

var _ store.AuditStore = (*webhookRecorder)(nil)
