// Command weekly-digest is a standalone, no-database smoke test for the
// weekly digest: the engine turning a week of audit history into a
// paragraph a human reads on a Monday morning, instead of a table
// somebody has to know SQL to query. What is under test is the whole
// path through the public facade — that real operations show up in the
// report, that the counts stay exact when the detail is capped, that a
// host's own event types are reported rather than dropped, that the
// window is honoured, and that building a report writes nothing.
//
// The last part is the point of the tier this belongs to: a digest
// informs a human and takes no action of its own, so the checks below
// include reading the same week twice and proving nothing moved.
// Run with:
//
//	go run ./cmd/smoketest/weekly-digest
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/notify"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
)

const (
	email    = "raymondproguy@dev.com"
	password = "Tr0ubl3-Fr33!2026"
	jwtKey   = "smoketest-jwt-secret-do-not-ship"
	goodIP   = "203.0.113.9"
	badIP    = "198.51.100.7"
	agent    = "smoketest-agent"
)

var failures int

func main() {
	fmt.Println("cryden — weekly digest smoke test")

	aWeekBecomesAReport()
	aQuietWeekIsShort()
	theCountsStayExactPastTheCap()
	theWindowIsAWindow()
	aHostsOwnEventTypesSurvive()
	webhooksDoNotHideTheDigest()
	nothingIsWritten()
	noSecretsInTheReport()
	aBrokenStoreIsAnError()

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
		return
	}
	fmt.Printf("%d CHECK(S) FAILED\n", failures)
	os.Exit(1)
}

// harness keeps the audit store the engine was built with, because two
// of the checks below are about what the host itself can put in there.
type harness struct {
	engine *cryden.Engine
	audit  store.AuditStore
	sender *recordingWebhookSender
}

func newHarness(sender *recordingWebhookSender) (*harness, bool) {
	audit := memory.NewAuditStore()
	cfg := cryden.Config{
		JWTSecret: jwtKey,
		Users:     memory.NewUserStore(),
		Sessions:  memory.NewSessionStore(),
		Audit:     audit,
		Logger:    logger.NewNopLogger(),
	}
	if sender != nil {
		cfg.Webhooks = sender
	}
	engine, err := cryden.New(cfg)
	if err != nil {
		fail(fmt.Sprintf("building the engine: %v", err))
		return nil, false
	}
	return &harness{engine: engine, audit: audit, sender: sender}, true
}

// history is the week every check reads: one signup, one good sign-in,
// then five bad ones, which is the default lockout threshold and so also
// records the account_locked event a digest spells out in full.
func (h *harness) history(ctx context.Context) bool {
	if _, err := cryden.SignUp(ctx, h.engine, email, password, goodIP); err != nil {
		fail(fmt.Sprintf("signing up: %v", err))
		return false
	}
	if _, err := cryden.Login(ctx, h.engine, email, password, goodIP, agent); err != nil {
		fail(fmt.Sprintf("signing in: %v", err))
		return false
	}
	for i := 0; i < 5; i++ {
		if _, err := cryden.Login(ctx, h.engine, email, "wrong-password", badIP, agent); err == nil {
			fail("a sign-in with the wrong password succeeded")
			return false
		}
	}
	return true
}

// The item itself: a week of real operations, summarised in English.
func aWeekBecomesAReport() {
	section("A week of history becomes a report")

	h, ok := newHarness(nil)
	if !ok || !h.history(context.Background()) {
		return
	}

	text, err := cryden.WeeklyDigest(context.Background(), h.engine)
	check("built the digest", err)

	expectLine(text, "the window is stated", "Security digest —")
	expectLine(text, "the window is seven days", "(7 days)")
	// One signup, one good sign-in, five failures and the lockout they
	// caused: every event the week produced, counted once.
	expectLine(text, "the total is counted", "8 events recorded in total.")
	expectLine(text, "the lockout leads the report", "Needs attention")
	expectLine(text, "the lockout is described, not numbered", "1 account was locked after repeated failed sign-ins")
	expectLine(text, "the signup is counted", "1 account was created")
	expectLine(text, "the good sign-in is counted", "1 sign-in succeeded")
	expectLine(text, "the bad sign-ins are counted", "5 sign-in attempts failed")
	expectLine(text, "the lockout names the IP behind it", "IP "+badIP)

	fmt.Println()
	fmt.Println(indent(text))
}

// A digest of a week where nothing happened should be one line, not a
// page of zeroes — the reason anybody keeps reading it every Monday.
func aQuietWeekIsShort() {
	section("A quiet week is short")

	h, ok := newHarness(nil)
	if !ok {
		return
	}

	text, err := cryden.WeeklyDigest(context.Background(), h.engine)
	check("built the digest", err)
	expectLine(text, "says so plainly", "Nothing to report")
	expectMissing(text, "prints no section headings", "Sign-ins")
	expectMissing(text, "prints no zero counts", " 0 ")
	expectTrue("stays under five lines", strings.Count(strings.TrimSpace(text), "\n") < 5)
}

// The cap bounds what the report prints, never what it knows: twelve
// lockouts are twelve in the count, with ten spelled out.
func theCountsStayExactPastTheCap() {
	section("The counts stay exact past the detail cap")

	h, ok := newHarness(nil)
	if !ok {
		return
	}
	ctx := context.Background()

	const locked = 12
	for i := 0; i < locked; i++ {
		address := fmt.Sprintf("locked-%02d@dev.com", i)
		// A distinct IP per account: signup is rate limited per caller
		// IP, and twelve accounts from one address is what that limit
		// exists to stop.
		ip := fmt.Sprintf("203.0.113.%d", 20+i)
		if _, err := cryden.SignUp(ctx, h.engine, address, password, ip); err != nil {
			fail(fmt.Sprintf("signing up %s: %v", address, err))
			return
		}
		for j := 0; j < 5; j++ {
			if _, err := cryden.Login(ctx, h.engine, address, "wrong-password", ip, agent); err == nil {
				fail("a sign-in with the wrong password succeeded")
				return
			}
		}
	}

	text, err := cryden.WeeklyDigest(ctx, h.engine)
	check("built the digest", err)
	expectLine(text, "all twelve lockouts are counted", "12 accounts were locked")
	expectLine(text, "ten of twelve are spelled out", "(the 10 most recent of 12 shown)")
	expectCount("exactly ten detail lines", countDetailLines(text), 10)
}

func theWindowIsAWindow() {
	section("The window is honoured")

	h, ok := newHarness(nil)
	if !ok || !h.history(context.Background()) {
		return
	}
	ctx := context.Background()

	future, err := cryden.DigestSince(ctx, h.engine, time.Now().Add(time.Hour))
	check("a window starting in the future is not an error", err)
	expectLine(future, "and holds nothing", "Nothing to report")

	day, err := cryden.DigestSince(ctx, h.engine, time.Now().Add(-24*time.Hour))
	check("a one-day window builds", err)
	expectLine(day, "and says it is one day", "(1 day)")
	expectLine(day, "and still holds today's history", "1 account was created")
}

// An engine that does not know an event type still reports it. This is
// what stops a digest from quietly hiding a host app's own security
// events, or the engine's own next added type.
func aHostsOwnEventTypesSurvive() {
	section("A host's own event types are reported, not dropped")

	h, ok := newHarness(nil)
	if !ok {
		return
	}
	ctx := context.Background()

	// The host writing into the same audit table it handed the engine —
	// the supported way to keep one timeline for the whole application.
	for i := 0; i < 3; i++ {
		if err := h.audit.Record(ctx, store.AuditEvent{
			Type:   store.AuditEventType("acme_invoice_paid"),
			UserID: "acme-user-1",
			IP:     goodIP,
		}); err != nil {
			fail(fmt.Sprintf("recording a host event: %v", err))
			return
		}
	}

	text, err := cryden.WeeklyDigest(ctx, h.engine)
	check("built the digest", err)
	expectLine(text, "the unknown type gets its own section", "Other events (types this engine does not define)")
	expectLine(text, "and its exact count", "3 acme_invoice_paid")
	expectLine(text, "and reaches the total", "3 events recorded in total.")
}

// Webhooks replace the engine's audit store with a decorator. A digest
// built through it must see the same history — the failure this guards
// against is a report that silently empties out for exactly the hosts
// that wired notifications up.
func webhooksDoNotHideTheDigest() {
	section("Webhooks do not hide the digest")

	sender := &recordingWebhookSender{}
	h, ok := newHarness(sender)
	if !ok || !h.history(context.Background()) {
		return
	}

	text, err := cryden.WeeklyDigest(context.Background(), h.engine)
	check("built the digest through the decorated store", err)
	expectTrue("webhooks were actually delivered", len(sender.delivered()) > 0)
	expectLine(text, "the signup is still counted", "1 account was created")
	expectLine(text, "the lockout is still described", "1 account was locked after repeated failed sign-ins")
}

// The tier's rule, checked rather than asserted: reading a digest is a
// read. Nothing is recorded, so the second read is byte-identical to the
// first below its clock-stamped header.
func nothingIsWritten() {
	section("Building a digest writes nothing")

	h, ok := newHarness(nil)
	if !ok || !h.history(context.Background()) {
		return
	}
	ctx := context.Background()

	before, err := h.audit.SearchByType(ctx, store.EventLoginFailed, 100)
	check("counted the history first", err)

	first, err := cryden.WeeklyDigest(ctx, h.engine)
	check("built the digest once", err)
	second, err := cryden.WeeklyDigest(ctx, h.engine)
	check("built the digest twice", err)

	after, err := h.audit.SearchByType(ctx, store.EventLoginFailed, 100)
	check("counted the history again", err)
	expectCount("the audit history did not grow", len(after), len(before))
	expectTrue("the second report matches the first", body(first) == body(second))
}

// A digest is meant to be mailed, pasted into a channel, or dropped into
// a ticket. Nothing that would be dangerous there may reach it.
func noSecretsInTheReport() {
	section("No secrets reach the report")

	h, ok := newHarness(nil)
	if !ok || !h.history(context.Background()) {
		return
	}

	text, err := cryden.WeeklyDigest(context.Background(), h.engine)
	check("built the digest", err)
	expectMissing(text, "no plaintext password", password)
	expectMissing(text, "no wrong password guess", "wrong-password")
	expectMissing(text, "no JWT signing secret", jwtKey)
	expectMissing(text, "no password hash", "$argon2")
	expectMissing(text, "no bare email address", email)
}

// The negative case a report has to get right: a store that cannot
// answer is an error, never a digest that reads like a quiet week.
// Silently reporting "nothing happened" because the database was down is
// the worst possible failure for this feature.
func aBrokenStoreIsAnError() {
	section("A broken store is an error, not a quiet week")

	countFails := errors.New("connection refused")
	engine, err := cryden.New(cryden.Config{
		JWTSecret: jwtKey,
		Users:     memory.NewUserStore(),
		Sessions:  memory.NewSessionStore(),
		Audit:     &brokenAuditStore{AuditStore: memory.NewAuditStore(), countErr: countFails},
		Logger:    logger.NewNopLogger(),
	})
	check("built an engine on a store whose counts fail", err)
	if err != nil {
		return
	}

	text, err := cryden.WeeklyDigest(context.Background(), engine)
	expectErrorIs("counting failed, so the digest failed", err, countFails)
	expectString("and returned no text at all", text, "")

	// The subtler half: counts work, detail does not. A digest that
	// dropped the detail here would name the right number of lockouts
	// and none of the accounts.
	searchFails := errors.New("statement timeout")
	audit := memory.NewAuditStore()
	if err := audit.Record(context.Background(), store.AuditEvent{Type: store.EventAccountLocked, UserID: "user-1"}); err != nil {
		fail(fmt.Sprintf("recording a lockout: %v", err))
		return
	}
	engine, err = cryden.New(cryden.Config{
		JWTSecret: jwtKey,
		Users:     memory.NewUserStore(),
		Sessions:  memory.NewSessionStore(),
		Audit:     &brokenAuditStore{AuditStore: audit, searchErr: searchFails},
		Logger:    logger.NewNopLogger(),
	})
	check("built an engine on a store whose detail reads fail", err)
	if err != nil {
		return
	}

	_, err = cryden.WeeklyDigest(context.Background(), engine)
	expectErrorIs("detail failed, so the digest failed", err, searchFails)
}

// brokenAuditStore is a store that is up enough to be configured and
// broken where it counts — the shape of a database mid-failover.
type brokenAuditStore struct {
	store.AuditStore
	countErr  error
	searchErr error
}

func (s *brokenAuditStore) CountByType(ctx context.Context, since time.Time) (map[store.AuditEventType]int, error) {
	if s.countErr != nil {
		return nil, s.countErr
	}
	return s.AuditStore.CountByType(ctx, since)
}

func (s *brokenAuditStore) SearchByType(ctx context.Context, eventType store.AuditEventType, limit int) ([]store.AuditEvent, error) {
	if s.searchErr != nil {
		return nil, s.searchErr
	}
	return s.AuditStore.SearchByType(ctx, eventType, limit)
}

// recordingWebhookSender is the shape a host app supplies: the engine
// reaches it only through notify.WebhookSender and never learns where
// the events go.
type recordingWebhookSender struct {
	events []notify.WebhookEvent
}

func (r *recordingWebhookSender) SendWebhook(ctx context.Context, event notify.WebhookEvent) error {
	r.events = append(r.events, event)
	return nil
}

func (r *recordingWebhookSender) delivered() []notify.WebhookEvent { return r.events }

var _ notify.WebhookSender = (*recordingWebhookSender)(nil)

// body drops the header line, whose "until" is a clock read and so
// differs between two reports of the same history.
func body(text string) string {
	_, rest, _ := strings.Cut(text, "\n")
	return rest
}

// countDetailLines counts the individual events a digest spelled out, as
// opposed to the count lines above them.
func countDetailLines(text string) int {
	n := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "    ") && strings.Contains(line, " — ") {
			n++
		}
	}
	return n
}

func indent(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		b.WriteString("    " + line + "\n")
	}
	return b.String()
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

func expectLine(text, step, want string) {
	if !strings.Contains(text, want) {
		fail(fmt.Sprintf("%s: the report has no %q", step, want))
		return
	}
	pass(step)
}

func expectMissing(text, step, unwanted string) {
	if strings.Contains(text, unwanted) {
		fail(fmt.Sprintf("%s: the report contains %q", step, unwanted))
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
