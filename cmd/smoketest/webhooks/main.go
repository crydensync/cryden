// Command webhooks is a standalone, no-database smoke test for outbound
// event notification: the engine handing the host app every subscribed
// event as it is recorded, so the host can email "your password was
// changed", page somebody on a lockout, or sync a signup into its CRM
// without polling the audit table. What is under test is the whole path
// through the public facade — that real operations deliver, that the
// default subset leaves out the high-volume events on purpose, that an
// explicit subset is honoured exactly, and that a broken sender costs
// the notification and never the login. The engine ships no
// implementation and makes no HTTP call; the sender here is a slice.
// Run with:
//
//	go run ./cmd/smoketest/webhooks
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/auth"
	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/notify"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
)

const (
	email       = "raymondproguy@dev.com"
	password    = "Tr0ubl3-Fr33!2026"
	newPassword = "An0th3r-Str0ng!2026"
	callerIP    = "203.0.113.7"
	agent       = "smoketest-agent"
)

var failures int

func main() {
	fmt.Println("cryden — webhooks smoke test")

	theRoundTrip()
	nothingConfiguredNothingChanged()
	theDefaultSubset()
	whatTheDefaultLeavesOut()
	anExplicitSubset()
	aBrokenSender()
	theAuditLogIsUnaffected()
	deliveryIDsAndContext()
	refusedConfiguration()
	whatIsActuallyDelivered()

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
		return
	}
	fmt.Printf("%d CHECK(S) FAILED\n", failures)
	os.Exit(1)
}

// The point of the item: something happened, and the host app is told
// without having to ask.
func theRoundTrip() {
	section("An event reaches the host app")

	h, ok := newHarness(nil)
	if !ok {
		return
	}
	ctx := context.Background()

	user, err := cryden.SignUp(ctx, h.engine, email, password, callerIP)
	check("signed up", err)

	expectCount("one webhook delivered", len(h.sender.all()), 1)
	if len(h.sender.all()) != 1 {
		return
	}
	event := h.sender.all()[0]
	expectString("it is signup_success", event.Type, string(store.EventSignupSuccess))
	expectString("it names the new user", event.UserID, user.ID)
	expectString("it carries the caller's IP", event.IP, callerIP)
	expectTrue("it carries a delivery ID", event.ID != "")
	expectTrue("its timestamp is UTC", event.OccurredAt.Location() == time.UTC)
	expectTrue("its timestamp is set", !event.OccurredAt.IsZero())

	// The webhook is a copy of the audit row, not a replacement for it.
	events := h.eventsFor(user.ID)
	expectTrue("the audit row was written too", hasEvent(events, store.EventSignupSuccess))
}

// A host that never sets Config.Webhooks runs the engine that existed
// before this feature did.
func nothingConfiguredNothingChanged() {
	section("Nothing configured, nothing changes")

	audit := memory.NewAuditStore()
	engine, err := cryden.New(cryden.Config{
		JWTSecret:         "smoketest-jwt-secret",
		Users:             memory.NewUserStore(),
		Sessions:          memory.NewSessionStore(),
		Audit:             audit,
		RateLimitAttempts: 1000,
		Logger:            logger.NewNopLogger(),
	})
	check("engine built with no sender", err)
	if err != nil {
		return
	}
	ctx := context.Background()

	user, err := cryden.SignUp(ctx, engine, email, password, callerIP)
	check("signup still works", err)
	_, err = cryden.Login(ctx, engine, email, password, callerIP, agent)
	check("login still works", err)

	events, err := audit.ListByUser(ctx, user.ID, 50)
	check("the audit log is readable", err)
	expectTrue("signup_success is still audited", hasEvent(events, store.EventSignupSuccess))
	expectTrue("login_success is still audited", hasEvent(events, store.EventLoginSuccess))
}

// The events a host app usually wants, triggered the way a host app
// triggers them: through the facade, one real operation at a time.
func theDefaultSubset() {
	section("The default subset, one real operation at a time")

	h, ok := newHarness(nil)
	if !ok {
		return
	}
	ctx := context.Background()

	user, err := cryden.SignUp(ctx, h.engine, email, password, callerIP)
	check("signed up", err)
	expectDelivered(h, "signup_success", store.EventSignupSuccess)

	_, key, err := cryden.GenerateAPIKey(ctx, h.engine, user.ID, "ci deploy", []string{"deploy:write"}, 0)
	check("api key generated", err)
	expectDelivered(h, "api_key_created", store.EventAPIKeyCreated)

	check("api key revoked", cryden.RevokeAPIKey(ctx, h.engine, user.ID, key.ID))
	expectDelivered(h, "api_key_revoked", store.EventAPIKeyRevoked)

	// recovery_codes_generated is in the default set too, but generating
	// them needs a second factor enrolled first — a TOTP dance this test
	// has no reason to perform. Six event types below is coverage enough.
	check("password changed", cryden.ChangePassword(ctx, h.engine, user.ID, password, newPassword))
	expectDelivered(h, "password_changed", store.EventPasswordChanged)

	check("account deleted", cryden.DeleteAccount(ctx, h.engine, user.ID, newPassword))
	expectDelivered(h, "account_deleted", store.EventAccountDeleted)

	// Five operations, five deliveries, in the order they happened.
	expectCount("five deliveries in total", len(h.sender.all()), 5)

	// The two that mean something has gone wrong need their own engine:
	// one that locks an account after two failures.
	locking, ok := newHarnessWithLockout(nil, 2)
	if !ok {
		return
	}
	lockedUser, err := cryden.SignUp(ctx, locking.engine, email, password, callerIP)
	check("signed up on the locking engine", err)
	locking.sender.reset()

	for i := 0; i < 2; i++ {
		if _, err := cryden.Login(ctx, locking.engine, email, "wrong-password", callerIP, agent); err == nil {
			fail("a wrong password logged in")
		}
	}
	expectErrorIs("the account is now locked",
		loginErr(ctx, locking.engine, email, password), auth.ErrAccountLocked)
	expectTrue("account_locked was delivered", locking.sender.has(store.EventAccountLocked))
	expectTrue("login_failed was not", !locking.sender.has(store.EventLoginFailed))
	if e, found := locking.sender.find(store.EventAccountLocked); found {
		expectString("the lockout names the account", e.UserID, lockedUser.ID)
	}

	// A refresh token presented twice: the second attempt is the signal
	// that somebody is holding a token they should not have.
	reuse, ok := newHarness(nil)
	if !ok {
		return
	}
	if _, err := cryden.SignUp(ctx, reuse.engine, email, password, callerIP); err != nil {
		fail(fmt.Sprintf("signing up on the reuse engine: %v", err))
		return
	}
	tokens, err := cryden.Login(ctx, reuse.engine, email, password, callerIP, agent)
	check("logged in for a refresh token", err)
	if _, err := cryden.RefreshToken(ctx, reuse.engine, tokens.RefreshToken); err != nil {
		fail(fmt.Sprintf("first refresh: %v", err))
		return
	}
	reuse.sender.reset()
	if _, err := cryden.RefreshToken(ctx, reuse.engine, tokens.RefreshToken); err == nil {
		fail("a spent refresh token was accepted")
	}
	expectTrue("token_reuse_detected was delivered", reuse.sender.has(store.EventTokenReuseDetected))
}

// The three left out on purpose, and the reason they are: volume nobody
// asked for, some of it chosen by an attacker.
func whatTheDefaultLeavesOut() {
	section("What the default subset leaves out")

	h, ok := newHarness(nil)
	if !ok {
		return
	}
	ctx := context.Background()

	if _, err := cryden.SignUp(ctx, h.engine, email, password, callerIP); err != nil {
		fail(fmt.Sprintf("signing up: %v", err))
		return
	}
	h.sender.reset()

	// Five logins and five refreshes: on a real deployment this is one
	// user for one afternoon.
	for i := 0; i < 5; i++ {
		tokens, err := cryden.Login(ctx, h.engine, email, password, callerIP, agent)
		if err != nil {
			fail(fmt.Sprintf("login %d: %v", i, err))
			return
		}
		if _, err := cryden.RefreshToken(ctx, h.engine, tokens.RefreshToken); err != nil {
			fail(fmt.Sprintf("refresh %d: %v", i, err))
			return
		}
	}
	expectCount("five logins and five refreshes deliver nothing", len(h.sender.all()), 0)

	// Logging out is the user's own doing in the host's own UI, so the
	// host already knows.
	tokens, err := cryden.Login(ctx, h.engine, email, password, callerIP, agent)
	check("logged in once more", err)
	sessions, err := cryden.ListPublicSessions(ctx, h.engine, h.userIDFor(ctx, email))
	check("sessions listed", err)
	if len(sessions) > 0 {
		check("logged out", cryden.Logout(ctx, h.engine, sessions[0].ID, h.userIDFor(ctx, email)))
	}
	_ = tokens
	expectCount("logout delivers nothing either", len(h.sender.all()), 0)

	// All of it is still in the audit log, which is the point of the
	// filter: it decides what is worth an outbound call, not what is
	// worth recording.
	events := h.eventsFor(h.userIDFor(ctx, email))
	expectTrue("login_success is audited", hasEvent(events, store.EventLoginSuccess))
	expectTrue("token_rotated is audited", hasEvent(events, store.EventTokenRotated))
	expectTrue("logout is audited", hasEvent(events, store.EventLogout))
}

// A host that wants the high-volume events can have them. The list is
// exactly the list — nothing added, nothing assumed.
func anExplicitSubset() {
	section("An explicit subset takes exact control")

	h, ok := newHarness([]store.AuditEventType{store.EventLoginSuccess})
	if !ok {
		return
	}
	ctx := context.Background()

	if _, err := cryden.SignUp(ctx, h.engine, email, password, callerIP); err != nil {
		fail(fmt.Sprintf("signing up: %v", err))
		return
	}
	expectCount("signup_success is not subscribed, so nothing is delivered", len(h.sender.all()), 0)

	for i := 0; i < 3; i++ {
		if _, err := cryden.Login(ctx, h.engine, email, password, callerIP, agent); err != nil {
			fail(fmt.Sprintf("login %d: %v", i, err))
			return
		}
	}
	expectCount("all three logins are delivered", len(h.sender.all()), 3)
	expectTrue("every one of them is login_success", onlyType(h.sender.all(), store.EventLoginSuccess))

	// DefaultWebhookEvents is a starting point, not a floor to build on.
	appended, ok := newHarness(append(cryden.DefaultWebhookEvents(), store.EventLoginSuccess))
	if !ok {
		return
	}
	if _, err := cryden.SignUp(ctx, appended.engine, email, password, callerIP); err != nil {
		fail(fmt.Sprintf("signing up: %v", err))
		return
	}
	if _, err := cryden.Login(ctx, appended.engine, email, password, callerIP, agent); err != nil {
		fail(fmt.Sprintf("login: %v", err))
		return
	}
	expectCount("the default set plus one delivers both", len(appended.sender.all()), 2)
	expectTrue("...signup_success", appended.sender.has(store.EventSignupSuccess))
	expectTrue("...and login_success", appended.sender.has(store.EventLoginSuccess))
}

// A webhook is a notification, not a gate. The operation it reports has
// already happened and is not undone because the host's queue is down.
func aBrokenSender() {
	section("A broken sender costs the notification, never the operation")

	audit := memory.NewAuditStore()
	sender := &recordingSender{err: errors.New("queue unreachable")}
	engine, err := cryden.New(cryden.Config{
		JWTSecret:         "smoketest-jwt-secret",
		Users:             memory.NewUserStore(),
		Sessions:          memory.NewSessionStore(),
		Audit:             audit,
		Webhooks:          sender,
		RateLimitAttempts: 1000,
		Logger:            logger.NewNopLogger(),
	})
	check("engine built with a failing sender", err)
	if err != nil {
		return
	}
	ctx := context.Background()

	user, err := cryden.SignUp(ctx, engine, email, password, callerIP)
	check("the signup succeeds anyway", err)
	_, err = cryden.Login(ctx, engine, email, password, callerIP, agent)
	check("and so does the login", err)

	expectCount("the send was attempted once", len(sender.all()), 1)
	events, err := audit.ListByUser(ctx, user.ID, 50)
	check("the audit log is readable", err)
	expectTrue("the audit row stands", hasEvent(events, store.EventSignupSuccess))

	// A panic is not an error. The engine recovers nowhere except across
	// a MultiLogger's sinks, where there is a second sink to keep the
	// record in — one sender has no second anything, so a panicking one
	// is a host bug that surfaces on the first request instead of
	// dropping events for months.
	panicking, err := cryden.New(cryden.Config{
		JWTSecret:         "smoketest-jwt-secret",
		Users:             memory.NewUserStore(),
		Sessions:          memory.NewSessionStore(),
		Audit:             memory.NewAuditStore(),
		Webhooks:          panickingSender{},
		RateLimitAttempts: 1000,
		Logger:            logger.NewNopLogger(),
	})
	check("engine built with a panicking sender", err)
	if err != nil {
		return
	}
	expectTrue("a panicking sender panics the operation", panicsOnSignUp(ctx, panicking))
}

// Delivery is filtered; recording is not. Everything the engine has
// always audited is still audited, and the reads a host queries it with
// are the wrapped store's own.
func theAuditLogIsUnaffected() {
	section("The audit log is untouched by the filter")

	h, ok := newHarness([]store.AuditEventType{store.EventAccountLocked})
	if !ok {
		return
	}
	ctx := context.Background()

	user, err := cryden.SignUp(ctx, h.engine, email, password, callerIP)
	check("signed up", err)
	_, err = cryden.Login(ctx, h.engine, email, password, callerIP, agent)
	check("logged in", err)

	expectCount("neither event was subscribed", len(h.sender.all()), 0)
	events := h.eventsFor(user.ID)
	expectCount("both were still recorded", len(events), 2)

	// SearchByType is the system-wide read the audit-reading features use.
	// Only Record is decorated, so this is the host's own store answering.
	byType, err := h.audit.SearchByType(ctx, store.EventLoginSuccess, 10)
	check("SearchByType still answers", err)
	expectCount("...with the login", len(byType), 1)
}

// The two things an implementation actually needs from the payload: a
// key to be idempotent on, and the request's context to trace by.
func deliveryIDsAndContext() {
	section("Delivery IDs and the caller's context")

	h, ok := newHarness(nil)
	if !ok {
		return
	}
	ctx := context.WithValue(context.Background(), traceKey{}, "trace-7f3a")

	user, err := cryden.SignUp(ctx, h.engine, email, password, callerIP)
	check("signed up with a trace ID in the context", err)
	check("password changed", cryden.ChangePassword(ctx, h.engine, user.ID, password, newPassword))

	delivered := h.sender.all()
	expectCount("two deliveries", len(delivered), 2)
	if len(delivered) != 2 {
		return
	}
	expectTrue("both carry an ID", delivered[0].ID != "" && delivered[1].ID != "")
	expectTrue("the IDs differ, so a receiver deduping on them keeps both",
		delivered[0].ID != delivered[1].ID)

	// The sender is called on the request's own goroutine with the
	// request's own context, so a host's tracing middleware is readable
	// from inside SendWebhook — which is how a queued event keeps its
	// trace.
	traces := h.sender.traces()
	expectCount("both sends saw a context", len(traces), 2)
	expectTrue("carrying the caller's trace ID", allEqual(traces, "trace-7f3a"))

	// Metadata is the audit event's own, and it is a copy: a sender that
	// keeps or edits the map cannot reach the audit record.
	if len(delivered[1].Metadata) > 0 {
		for k := range delivered[1].Metadata {
			delivered[1].Metadata[k] = "tampered"
		}
	}
	events := h.eventsFor(user.ID)
	expectTrue("editing a delivery does not reach the audit row",
		!hasMetadataValue(events, "tampered"))
}

// Two config mistakes that are silence at runtime, so they are errors at
// construction instead.
func refusedConfiguration() {
	section("Configuration the engine refuses")

	base := func() cryden.Config {
		return cryden.Config{
			JWTSecret: "smoketest-jwt-secret",
			Users:     memory.NewUserStore(),
			Sessions:  memory.NewSessionStore(),
			Audit:     memory.NewAuditStore(),
			Logger:    logger.NewNopLogger(),
		}
	}

	cfg := base()
	cfg.WebhookEvents = []store.AuditEventType{store.EventAccountLocked}
	_, err := cryden.New(cfg)
	expectErrorIs("a subscription with nowhere to deliver", err, cryden.ErrMissingWebhookSender)

	cfg = base()
	cfg.Webhooks = &recordingSender{}
	cfg.WebhookEvents = []store.AuditEventType{store.EventAccountLocked, ""}
	_, err = cryden.New(cfg)
	expectErrorIs("an empty event type", err, cryden.ErrInvalidWebhookEvent)

	// An unrecognised type is not an error — there is no canonical list
	// to check against — it simply never matches anything.
	cfg = base()
	sender := &recordingSender{}
	cfg.Webhooks = sender
	cfg.WebhookEvents = []store.AuditEventType{"acount_locked"}
	engine, err := cryden.New(cfg)
	check("a typo'd event type builds", err)
	if err == nil {
		if _, err := cryden.SignUp(context.Background(), engine, email, password, callerIP); err != nil {
			fail(fmt.Sprintf("signing up: %v", err))
		}
		expectCount("...and delivers nothing, ever", len(sender.all()), 0)
	}
}

// Printed rather than asserted: the shape of what a sender receives.
func whatIsActuallyDelivered() {
	section("What is actually delivered")

	h, ok := newHarness(nil)
	if !ok {
		return
	}
	ctx := context.Background()

	user, err := cryden.SignUp(ctx, h.engine, email, password, callerIP)
	if err != nil {
		fail(fmt.Sprintf("signing up: %v", err))
		return
	}
	if _, _, err := cryden.GenerateAPIKey(ctx, h.engine, user.ID, "ci deploy", []string{"deploy:write", "read"}, 0); err != nil {
		fail(fmt.Sprintf("generating a key: %v", err))
		return
	}

	for _, e := range h.sender.all() {
		fmt.Printf("  %s\n", e.Type)
		fmt.Printf("    ID:         %s\n", e.ID)
		fmt.Printf("    UserID:     %s\n", e.UserID)
		fmt.Printf("    IP:         %s\n", e.IP)
		fmt.Printf("    OccurredAt: %s\n", e.OccurredAt.Format("2006-01-02T15:04:05.000Z07:00"))
		fmt.Printf("    Metadata:   %s\n", formatMetadata(e.Metadata))
	}
	pass("the payload is the audit event's own fields, nothing invented")
	// Nothing secret travels in one: no password, no token, no key. The
	// api_key_created delivery above carries the key's id and prefix,
	// which is all the engine itself keeps.
	expectTrue("no delivery contains the password", !anyContains(h.sender.all(), password))
}

// ---- harness ----

type traceKey struct{}

// recordingSender is what a host app writes, minus the part that makes
// an HTTP call: it keeps what it was given and reports whether it
// worked. A real one enqueues here and lets something else deliver.
type recordingSender struct {
	mu     sync.Mutex
	events []notify.WebhookEvent
	seen   []string
	err    error
}

func (r *recordingSender) SendWebhook(ctx context.Context, event notify.WebhookEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	trace, _ := ctx.Value(traceKey{}).(string)
	r.seen = append(r.seen, trace)
	return r.err
}

func (r *recordingSender) all() []notify.WebhookEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]notify.WebhookEvent(nil), r.events...)
}

func (r *recordingSender) traces() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func (r *recordingSender) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = nil
	r.seen = nil
}

func (r *recordingSender) has(want store.AuditEventType) bool {
	_, found := r.find(want)
	return found
}

func (r *recordingSender) find(want store.AuditEventType) (notify.WebhookEvent, bool) {
	for _, e := range r.all() {
		if e.Type == string(want) {
			return e, true
		}
	}
	return notify.WebhookEvent{}, false
}

var _ notify.WebhookSender = (*recordingSender)(nil)

// panickingSender is the host bug the engine deliberately does not hide.
type panickingSender struct{}

func (panickingSender) SendWebhook(context.Context, notify.WebhookEvent) error {
	panic("the host's queue client panicked")
}

type harness struct {
	engine *cryden.Engine
	audit  *memory.AuditStore
	users  *memory.UserStore
	sender *recordingSender
}

// newHarness builds an engine with a webhook sender wired in. A nil
// events slice takes the default subset.
func newHarness(events []store.AuditEventType) (*harness, bool) {
	return newHarnessWithLockout(events, 0)
}

func newHarnessWithLockout(events []store.AuditEventType, lockoutThreshold int) (*harness, bool) {
	audit := memory.NewAuditStore()
	users := memory.NewUserStore()
	sender := &recordingSender{}
	engine, err := cryden.New(cryden.Config{
		JWTSecret:     "smoketest-jwt-secret",
		Users:         users,
		Sessions:      memory.NewSessionStore(),
		Audit:         audit,
		APIKeys:       memory.NewAPIKeyStore(),
		RecoveryCodes: memory.NewRecoveryCodeStore(),
		Webhooks:      sender,
		WebhookEvents: events,
		// Repeated logins from one address are this test's normal shape,
		// not an attack on it.
		RateLimitAttempts: 1000,
		LockoutThreshold:  lockoutThreshold,
		// The engine logs several lines per call; this test is about the
		// ✓/✗ lines, so those go nowhere.
		Logger: logger.NewNopLogger(),
	})
	if err != nil {
		fail(fmt.Sprintf("building the engine: %v", err))
		return nil, false
	}
	return &harness{engine: engine, audit: audit, users: users, sender: sender}, true
}

func (h *harness) eventsFor(userID string) []store.AuditEvent {
	events, err := h.audit.ListByUser(context.Background(), userID, 50)
	if err != nil {
		fail(fmt.Sprintf("listing audit events: %v", err))
		return nil
	}
	return events
}

func (h *harness) userIDFor(ctx context.Context, address string) string {
	user, err := h.users.GetByEmail(ctx, address)
	if err != nil {
		fail(fmt.Sprintf("looking up %s: %v", address, err))
		return ""
	}
	return user.ID
}

// ---- assertions ----

// expectDelivered asserts that the most recent delivery is want, which
// is what "this operation notified the host" looks like from outside.
func expectDelivered(h *harness, step string, want store.AuditEventType) {
	delivered := h.sender.all()
	if len(delivered) == 0 {
		fail(fmt.Sprintf("%s: nothing was delivered", step))
		return
	}
	if got := delivered[len(delivered)-1].Type; got != string(want) {
		fail(fmt.Sprintf("%s: the last delivery was %s", step, got))
		return
	}
	pass(step + " → delivered")
}

func loginErr(ctx context.Context, e *cryden.Engine, address, pass string) error {
	_, err := cryden.Login(ctx, e, address, pass, callerIP, agent)
	return err
}

func panicsOnSignUp(ctx context.Context, e *cryden.Engine) (panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
	}()
	_, _ = cryden.SignUp(ctx, e, email, password, callerIP)
	return false
}

func hasEvent(events []store.AuditEvent, want store.AuditEventType) bool {
	for _, e := range events {
		if e.Type == want {
			return true
		}
	}
	return false
}

func hasMetadataValue(events []store.AuditEvent, value string) bool {
	for _, e := range events {
		for _, v := range e.Metadata {
			if v == value {
				return true
			}
		}
	}
	return false
}

func onlyType(events []notify.WebhookEvent, want store.AuditEventType) bool {
	for _, e := range events {
		if e.Type != string(want) {
			return false
		}
	}
	return len(events) > 0
}

func allEqual(got []string, want string) bool {
	for _, g := range got {
		if g != want {
			return false
		}
	}
	return len(got) > 0
}

func anyContains(events []notify.WebhookEvent, needle string) bool {
	for _, e := range events {
		for k, v := range e.Metadata {
			if strings.Contains(k, needle) || strings.Contains(v, needle) {
				return true
			}
		}
		if strings.Contains(e.ID, needle) || strings.Contains(e.UserID, needle) {
			return true
		}
	}
	return false
}

func formatMetadata(metadata map[string]string) string {
	if len(metadata) == 0 {
		return "(none)"
	}
	keys := make([]string, 0, len(metadata))
	for k := range metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%q", k, metadata[k]))
	}
	return strings.Join(parts, " ")
}

func section(name string) {
	fmt.Printf("\n— %s\n", name)
}

func check(step string, err error) {
	if err != nil {
		fail(fmt.Sprintf("%s: unexpected error: %v", step, err))
		return
	}
	pass(step)
}

func expectErrorIs(step string, got, want error) {
	if !errors.Is(got, want) {
		fail(fmt.Sprintf("%s: got %v, want %v", step, got, want))
		return
	}
	pass(fmt.Sprintf("%s → %v", step, want))
}

func expectString(step, got, want string) {
	if got != want {
		fail(fmt.Sprintf("%s: got %q, want %q", step, got, want))
		return
	}
	pass(step)
}

func expectCount(step string, got, want int) {
	if got != want {
		fail(fmt.Sprintf("%s: got %d, want %d", step, got, want))
		return
	}
	pass(step)
}

func expectTrue(step string, ok bool) {
	if !ok {
		fail(step)
		return
	}
	pass(step)
}

func pass(step string) {
	fmt.Println("✓", step)
}

func fail(msg string) {
	failures++
	fmt.Println("✗", msg)
}
