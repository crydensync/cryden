package cryden

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/notify"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
)

// recordingWebhookSender is the shape a host app supplies: something the
// engine only ever reaches through notify.WebhookSender, with no idea
// whether the events end up on a queue, in a test slice, or nowhere.
type recordingWebhookSender struct {
	mu       sync.Mutex
	events   []notify.WebhookEvent
	contexts []context.Context
	err      error
}

func (r *recordingWebhookSender) SendWebhook(ctx context.Context, event notify.WebhookEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	r.contexts = append(r.contexts, ctx)
	return r.err
}

func (r *recordingWebhookSender) types() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.events))
	for _, e := range r.events {
		out = append(out, e.Type)
	}
	return out
}

var _ notify.WebhookSender = (*recordingWebhookSender)(nil)

// failingAuditStore is a store whose writes fail while its reads work —
// the shape of a database that is up but out of disk.
type failingAuditStore struct {
	store.AuditStore
	err error
}

func (f *failingAuditStore) Record(context.Context, store.AuditEvent) error { return f.err }

// failingIDGenerator stands in for crypto/rand being unavailable.
type failingIDGenerator struct{}

func (failingIDGenerator) New() (string, error) { return "", errors.New("no entropy") }

var _ security.IDGenerator = failingIDGenerator{}

// newTestRecorder wires a recorder over an in-memory audit store,
// subscribed to exactly the events named.
func newTestRecorder(events ...store.AuditEventType) (*webhookRecorder, *memory.AuditStore, *recordingWebhookSender) {
	audit := memory.NewAuditStore()
	sender := &recordingWebhookSender{}
	return newWebhookRecorder(audit, sender, events, security.NewUUIDv7Generator(), logger.NewNopLogger()), audit, sender
}

func TestWebhookRecorder_DeliversASubscribedEvent(t *testing.T) {
	recorder, _, sender := newTestRecorder(store.EventAccountLocked)
	before := time.Now().UTC()

	err := recorder.Record(context.Background(), store.AuditEvent{
		Type:     store.EventAccountLocked,
		UserID:   "user-1",
		IP:       "1.2.3.4",
		Metadata: map[string]string{"attempts": "5"},
	})
	if err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	if len(sender.events) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(sender.events))
	}
	got := sender.events[0]
	if got.Type != string(store.EventAccountLocked) {
		t.Errorf("Type: got %q", got.Type)
	}
	if got.UserID != "user-1" || got.IP != "1.2.3.4" {
		t.Errorf("UserID/IP: got %q/%q", got.UserID, got.IP)
	}
	if got.Metadata["attempts"] != "5" {
		t.Errorf("Metadata: got %v", got.Metadata)
	}
	// An idempotency key the host can dedupe on, and a timestamp in UTC
	// rather than whatever zone the server happens to run in.
	if got.ID == "" {
		t.Error("expected a delivery ID")
	}
	if got.OccurredAt.Location() != time.UTC {
		t.Errorf("OccurredAt not UTC: %v", got.OccurredAt)
	}
	if got.OccurredAt.Before(before) || got.OccurredAt.After(time.Now().UTC()) {
		t.Errorf("OccurredAt outside the call: %v", got.OccurredAt)
	}
}

func TestWebhookRecorder_IgnoresAnUnsubscribedEvent(t *testing.T) {
	recorder, audit, sender := newTestRecorder(store.EventAccountLocked)

	if err := recorder.Record(context.Background(), store.AuditEvent{
		Type:   store.EventLoginSuccess,
		UserID: "user-1",
	}); err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	if len(sender.events) != 0 {
		t.Errorf("expected no delivery, got %v", sender.types())
	}
	// Filtered for delivery, not for the audit log: the row is still there.
	events, _ := audit.ListByUser(context.Background(), "user-1", 10)
	if len(events) != 1 {
		t.Errorf("expected the event to still be audited, got %d rows", len(events))
	}
}

// Two IDs from two events, so a receiver deduping on ID does not collapse
// them into one.
func TestWebhookRecorder_GivesEachEventItsOwnID(t *testing.T) {
	recorder, _, sender := newTestRecorder(store.EventPasswordChanged)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if err := recorder.Record(ctx, store.AuditEvent{Type: store.EventPasswordChanged, UserID: "user-1"}); err != nil {
			t.Fatalf("Record failed: %v", err)
		}
	}
	if len(sender.events) != 2 {
		t.Fatalf("expected 2 deliveries, got %d", len(sender.events))
	}
	if sender.events[0].ID == sender.events[1].ID {
		t.Errorf("both deliveries carried ID %q", sender.events[0].ID)
	}
}

// A sender that keeps the map it was handed must not be able to rewrite
// history in the audit store, which holds the same map by reference.
func TestWebhookRecorder_MetadataIsACopy(t *testing.T) {
	recorder, audit, sender := newTestRecorder(store.EventAnomalyDetected)
	ctx := context.Background()

	if err := recorder.Record(ctx, store.AuditEvent{
		Type:     store.EventAnomalyDetected,
		UserID:   "user-1",
		Metadata: map[string]string{"signals": "new_ip"},
	}); err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	sender.events[0].Metadata["signals"] = "tampered"
	sender.events[0].Metadata["extra"] = "added"

	events, _ := audit.ListByUser(ctx, "user-1", 10)
	if len(events) != 1 {
		t.Fatalf("expected 1 audited event, got %d", len(events))
	}
	if events[0].Metadata["signals"] != "new_ip" || len(events[0].Metadata) != 1 {
		t.Errorf("the audit record was reachable through the delivery: %v", events[0].Metadata)
	}
}

func TestWebhookRecorder_NilMetadataStaysNil(t *testing.T) {
	recorder, _, sender := newTestRecorder(store.EventLogout)

	if err := recorder.Record(context.Background(), store.AuditEvent{Type: store.EventLogout}); err != nil {
		t.Fatalf("Record failed: %v", err)
	}
	if sender.events[0].Metadata != nil {
		t.Errorf("expected nil metadata, got %v", sender.events[0].Metadata)
	}
}

// A webhook is a notification, not a gate: the operation that triggered
// it has already happened and is not undone because the host's queue is
// full.
func TestWebhookRecorder_ASendErrorDoesNotFailTheRecord(t *testing.T) {
	audit := memory.NewAuditStore()
	sender := &recordingWebhookSender{err: errors.New("queue full")}
	recorder := newWebhookRecorder(audit, sender, []store.AuditEventType{store.EventSignupSuccess},
		security.NewUUIDv7Generator(), logger.NewNopLogger())
	ctx := context.Background()

	if err := recorder.Record(ctx, store.AuditEvent{Type: store.EventSignupSuccess, UserID: "user-1"}); err != nil {
		t.Fatalf("expected the send error to be swallowed, got %v", err)
	}
	if len(sender.events) != 1 {
		t.Errorf("expected the send to have been attempted once, got %d", len(sender.events))
	}
	events, _ := audit.ListByUser(ctx, "user-1", 10)
	if len(events) != 1 {
		t.Errorf("expected the audit row to stand, got %d", len(events))
	}
}

// The audit write and the delivery are independent: an event that
// happened is worth reporting even when the row recording it did not
// land, and the store's error still reaches the caller unchanged.
func TestWebhookRecorder_DeliversEvenWhenTheAuditWriteFails(t *testing.T) {
	storeErr := errors.New("disk full")
	failing := &failingAuditStore{AuditStore: memory.NewAuditStore(), err: storeErr}
	sender := &recordingWebhookSender{}
	recorder := newWebhookRecorder(failing, sender, []store.AuditEventType{store.EventTokenReuseDetected},
		security.NewUUIDv7Generator(), logger.NewNopLogger())

	err := recorder.Record(context.Background(), store.AuditEvent{
		Type:   store.EventTokenReuseDetected,
		UserID: "user-1",
	})
	if !errors.Is(err, storeErr) {
		t.Errorf("expected the store's own error back, got %v", err)
	}
	if len(sender.events) != 1 {
		t.Errorf("expected the event to be delivered anyway, got %d", len(sender.events))
	}
}

// The delivery matters more than its idempotency key: a broken ID
// generator costs the key, not the notification.
func TestWebhookRecorder_DeliversWithoutAnIDWhenGenerationFails(t *testing.T) {
	sender := &recordingWebhookSender{}
	recorder := newWebhookRecorder(memory.NewAuditStore(), sender,
		[]store.AuditEventType{store.EventAccountDeleted}, failingIDGenerator{}, logger.NewNopLogger())

	if err := recorder.Record(context.Background(), store.AuditEvent{Type: store.EventAccountDeleted}); err != nil {
		t.Fatalf("Record failed: %v", err)
	}
	if len(sender.events) != 1 {
		t.Fatalf("expected the event to be delivered, got %d", len(sender.events))
	}
	if sender.events[0].ID != "" {
		t.Errorf("expected an empty ID, got %q", sender.events[0].ID)
	}
}

// The host's sender gets the triggering request's context, so whatever
// its middleware put in there — a trace ID, a tenant — is readable.
func TestWebhookRecorder_PassesTheCallersContext(t *testing.T) {
	recorder, _, sender := newTestRecorder(store.EventEmailChanged)
	ctx := context.WithValue(context.Background(), facadeTraceKey{}, "trace-xyz")

	if err := recorder.Record(ctx, store.AuditEvent{Type: store.EventEmailChanged}); err != nil {
		t.Fatalf("Record failed: %v", err)
	}
	if got, _ := sender.contexts[0].Value(facadeTraceKey{}).(string); got != "trace-xyz" {
		t.Errorf("expected the caller's context, got trace %q", got)
	}
}

// Only Record is decorated. Everything a host queries the audit log with
// is the wrapped store's, which is what keeps this transparent to the
// AI reporting features that read it.
func TestWebhookRecorder_ReadsPassThrough(t *testing.T) {
	recorder, audit, _ := newTestRecorder(store.EventLoginSuccess)
	ctx := context.Background()

	if err := audit.Record(ctx, store.AuditEvent{Type: store.EventLoginFailed, UserID: "user-1"}); err != nil {
		t.Fatalf("seeding failed: %v", err)
	}

	byUser, err := recorder.ListByUser(ctx, "user-1", 10)
	if err != nil || len(byUser) != 1 {
		t.Errorf("ListByUser: got %d rows, %v", len(byUser), err)
	}
	byType, err := recorder.SearchByType(ctx, store.EventLoginFailed, 10)
	if err != nil || len(byType) != 1 {
		t.Errorf("SearchByType: got %d rows, %v", len(byType), err)
	}
}

// The three excluded by volume are the three worth pinning: adding one
// later should be a decision somebody makes, not a diff nobody notices.
func TestDefaultWebhookEvents_ExcludesTheHighVolumeEvents(t *testing.T) {
	subscribed := make(map[store.AuditEventType]bool)
	for _, e := range DefaultWebhookEvents() {
		subscribed[e] = true
	}

	for _, e := range []store.AuditEventType{store.EventLoginSuccess, store.EventLoginFailed, store.EventTokenRotated} {
		if subscribed[e] {
			t.Errorf("%s is in the default set", e)
		}
	}
	for _, e := range []store.AuditEventType{
		store.EventSignupSuccess, store.EventAccountLocked, store.EventPasswordChanged,
		store.EventEmailChanged, store.EventAccountDeleted, store.EventTokenReuseDetected,
		store.EventTOTPDisabled, store.EventAPIKeyCreated, store.EventCredentialStuffingDetected,
	} {
		if !subscribed[e] {
			t.Errorf("%s is missing from the default set", e)
		}
	}
}

// Documented as append-able, so appending must not reach the next caller.
func TestDefaultWebhookEvents_ReturnsAFreshSlice(t *testing.T) {
	first := DefaultWebhookEvents()
	n := len(first)
	first[0] = store.EventLoginSuccess
	first = append(first, store.EventTokenRotated)
	_ = first

	second := DefaultWebhookEvents()
	if len(second) != n {
		t.Errorf("expected %d events, got %d", n, len(second))
	}
	if second[0] == store.EventLoginSuccess {
		t.Error("the default set was edited by a previous caller")
	}
}

func TestNew_RejectsWebhookEventsWithoutASender(t *testing.T) {
	cfg := validConfig()
	cfg.WebhookEvents = []store.AuditEventType{store.EventAccountLocked}
	if _, err := New(cfg); err != ErrMissingWebhookSender {
		t.Errorf("expected ErrMissingWebhookSender, got %v", err)
	}
}

func TestNew_RejectsAnEmptyWebhookEvent(t *testing.T) {
	cfg := validConfig()
	cfg.Webhooks = &recordingWebhookSender{}
	cfg.WebhookEvents = []store.AuditEventType{store.EventAccountLocked, ""}
	if _, err := New(cfg); err != ErrInvalidWebhookEvent {
		t.Errorf("expected ErrInvalidWebhookEvent, got %v", err)
	}
}

// A host not using this feature runs the audit path it ran before the
// feature existed — same store, no wrapper, nothing to filter.
func TestNew_LeavesTheAuditStoreUndecoratedWithoutWebhooks(t *testing.T) {
	cfg := validConfig()
	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, wrapped := engine.audit.(*webhookRecorder); wrapped {
		t.Error("the audit store was decorated without Config.Webhooks")
	}
	if engine.audit != cfg.Audit {
		t.Error("the audit store is not the one that was configured")
	}
}

// Wiring a sender into Config has to reach the real call paths, not just
// the Engine struct: signup and a password change are audited in two
// different files, and login is audited in a third that must stay quiet.
func TestWebhooks_TheDefaultSubsetThroughTheFacade(t *testing.T) {
	sender := &recordingWebhookSender{}
	cfg := validConfig()
	cfg.Webhooks = sender
	cfg.Logger = logger.NewNopLogger()
	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx := context.Background()

	user, err := SignUp(ctx, engine, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4")
	if err != nil {
		t.Fatalf("signup failed: %v", err)
	}
	if got := sender.types(); len(got) != 1 || got[0] != string(store.EventSignupSuccess) {
		t.Fatalf("after signup, expected [signup_success], got %v", got)
	}
	if sender.events[0].UserID != user.ID {
		t.Errorf("delivery named %q, the new user is %q", sender.events[0].UserID, user.ID)
	}

	if _, err := Login(ctx, engine, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent"); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if got := sender.types(); len(got) != 1 {
		t.Errorf("login_success is not in the default set, but %v was delivered", got)
	}

	if err := ChangePassword(ctx, engine, user.ID, "Tr0ubl3-Fr33!2026", "An0th3r-Str0ng!2026"); err != nil {
		t.Fatalf("password change failed: %v", err)
	}
	if got := sender.types(); len(got) != 2 || got[1] != string(store.EventPasswordChanged) {
		t.Errorf("expected password_changed second, got %v", got)
	}
}

// An explicit list is exactly the list — including the high-volume events
// the default refuses, for a host that has decided it wants them.
func TestWebhooks_AnExplicitSubsetTakesExactControl(t *testing.T) {
	sender := &recordingWebhookSender{}
	cfg := validConfig()
	cfg.Webhooks = sender
	cfg.WebhookEvents = []store.AuditEventType{store.EventLoginSuccess}
	cfg.Logger = logger.NewNopLogger()
	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx := context.Background()

	if _, err := SignUp(ctx, engine, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4"); err != nil {
		t.Fatalf("signup failed: %v", err)
	}
	if got := sender.types(); len(got) != 0 {
		t.Errorf("signup_success was not subscribed, but %v was delivered", got)
	}

	if _, err := Login(ctx, engine, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent"); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if got := sender.types(); len(got) != 1 || got[0] != string(store.EventLoginSuccess) {
		t.Errorf("expected [login_success], got %v", got)
	}
}
