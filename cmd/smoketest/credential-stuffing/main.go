// Command credential-stuffing is a standalone, no-database smoke test
// for credential-stuffing detection: one IP failing against many
// different accounts, the unknown-email variant of the same spray, the
// repeated-failures-against-one-account case that is deliberately NOT a
// spray, cooldown suppression, and — the property the whole feature
// rests on — that a flagged login still succeeds. Run with:
//
//	go run ./cmd/smoketest/credential-stuffing
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
)

const (
	email    = "raymondproguy@dev.com"
	password = "Tr0ubl3-Fr33!2026"

	knownIP    = "1.2.3.4"
	sprayIP    = "203.0.113.9"
	knownAgent = "cryden-smoketest/1.0"
	// The one password an attacker tries against every account on a
	// list — the shape of the attack, in one constant.
	leakedPassword = "hunter2-from-some-other-breach"
)

// Small enough that a spray is five calls, not ten. Cooldown is off by
// default so every crossing is visible; the cooldown scenario sets it.
var thresholds = security.CredentialStuffingThresholds{
	Window:         15 * time.Minute,
	TargetAccounts: 5,
}

// Small per-account thresholds so the one scenario that needs to prove
// item 8 still runs can see it fire.
var anomalyThresholds = security.AnomalyThresholds{
	Window:                15 * time.Minute,
	HistorySize:           20,
	UserFailureVelocity:   3,
	IPFailureVelocity:     5,
	MaxConcurrentSessions: 50,
	TokenReuseLookback:    24 * time.Hour,
}

var failures int

// rig is one isolated engine plus the stores the checks read back from.
// Each scenario gets a fresh one so event counts never bleed between
// them.
type rig struct {
	engine    *cryden.Engine
	audit     *memory.AuditStore
	anomalies *memory.AnomalyStore
	userID    string
}

func newRig(ctx context.Context, detectionOn bool) (*rig, error) {
	return newRigWith(ctx, detectionOn, thresholds)
}

func newRigWith(ctx context.Context, detectionOn bool, th security.CredentialStuffingThresholds) (*rig, error) {
	r := &rig{
		audit:     memory.NewAuditStore(),
		anomalies: memory.NewAnomalyStore(),
	}
	cfg := cryden.Config{
		JWTSecret:                    "smoketest-jwt-secret",
		Users:                        memory.NewUserStore(),
		Sessions:                     memory.NewSessionStore(),
		Audit:                        r.audit,
		AnomalyThresholds:            anomalyThresholds,
		CredentialStuffingThresholds: th,
		// Both raised so neither fires first and masks what this smoke
		// test is about: hammering one account would otherwise lock it,
		// and a spray needs more attempts than the default rate limit
		// allows from one address.
		LockoutThreshold:  100,
		RateLimitAttempts: 1000,
	}
	if detectionOn {
		cfg.Anomalies = r.anomalies
	}
	engine, err := cryden.New(cfg)
	if err != nil {
		return nil, err
	}
	r.engine = engine

	user, err := cryden.SignUp(ctx, engine, email, password, knownIP)
	if err != nil {
		return nil, err
	}
	r.userID = user.ID
	return r, nil
}

// seedVictims registers n more accounts for a spray to aim at.
func (r *rig) seedVictims(ctx context.Context, n int) {
	for i := 1; i <= n; i++ {
		if _, err := cryden.SignUp(ctx, r.engine, victimEmail(i), password, knownIP); err != nil {
			fail(fmt.Sprintf("seeding %s: %v", victimEmail(i), err))
			return
		}
	}
	pass(fmt.Sprintf("%d more accounts registered for the spray to aim at", n))
}

func victimEmail(i int) string  { return "victim-" + strconv.Itoa(i) + "@dev.com" }
func unknownEmail(i int) string { return "nobody-" + strconv.Itoa(i) + "@dev.com" }

func (r *rig) login(ctx context.Context, addr, pass, ip string) error {
	_, err := cryden.Login(ctx, r.engine, addr, pass, ip, knownAgent)
	return err
}

// events returns every credential-stuffing event recorded so far,
// oldest first.
func (r *rig) events(ctx context.Context) []store.AuditEvent {
	found, err := r.audit.SearchByType(ctx, store.EventCredentialStuffingDetected, 200)
	if err != nil {
		fail(fmt.Sprintf("reading audit events: %v", err))
		return nil
	}
	// SearchByType is newest-first; walk backwards for chronological
	// order so an event's position matches the attempt that caused it.
	out := make([]store.AuditEvent, 0, len(found))
	for i := len(found) - 1; i >= 0; i-- {
		out = append(out, found[i])
	}
	return out
}

func (r *rig) signals(ctx context.Context) []string {
	var out []string
	for _, e := range r.events(ctx) {
		out = append(out, e.Metadata["signals"])
	}
	return out
}

func main() {
	ctx := context.Background()

	sprayAcrossAccounts(ctx)
	unknownEmailSpray(ctx)
	oneAccountHammered(ctx)
	successFromASprayingIP(ctx)
	cooldown(ctx)
	detectionOff(ctx)
	silencedIndependently(ctx)

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
		return
	}
	fmt.Printf("%d CHECK(S) FAILED\n", failures)
	os.Exit(1)
}

// The attack this feature exists for: one password, many accounts. Each
// account sees a single failure, so per-account lockout never fires and
// nothing in item 8's per-account signals notices.
func sprayAcrossAccounts(ctx context.Context) {
	fmt.Println("— one IP, one password, many accounts")
	r, err := newRig(ctx, true)
	check("engine constructed with an AnomalyStore", err)
	if r == nil {
		return
	}
	r.seedVictims(ctx, thresholds.TargetAccounts)

	// Four targets is under the bar. The threshold is inclusive, so the
	// fifth is the one that trips it.
	for i := 1; i < thresholds.TargetAccounts; i++ {
		checkExpectError(fmt.Sprintf("attempt against %s rejected (%d targets so far)", victimEmail(i), i),
			r.login(ctx, victimEmail(i), leakedPassword, sprayIP))
	}
	expectSignals(ctx, r, "a spray under the threshold is not flagged")

	checkExpectError("attempt against the fifth account rejected",
		r.login(ctx, victimEmail(thresholds.TargetAccounts), leakedPassword, sprayIP))
	expectSignals(ctx, r, "the crossing attempt flags the address", "account_spray")

	events := r.events(ctx)
	if len(events) == 1 {
		expectMeta("the event carries the breadth it measured", events[0], "distinct_accounts", "5")
		expectMeta("no unknown targets in a spray against real accounts", events[0], "unknown_targets", "0")
		expectString("the event names the source address", events[0].IP, sprayIP)
	}

	// The same rows, read the two ways the two features read them.
	since := time.Now().Add(-thresholds.Window)
	counts, err := r.anomalies.CountTargetsForIP(ctx, sprayIP, since)
	check("per-IP breadth read back from the store", err)
	expectCount("five distinct accounts were targeted", counts.DistinctAccounts, 5)
	attempts, err := r.anomalies.CountFailuresForIP(ctx, sprayIP, since)
	check("per-IP failure count read back", err)
	expectCount("one attempt per account", attempts, 5)
}

// A list bought elsewhere mostly names addresses that were never
// registered here. Those attempts carry no user ID at all, so they are
// only ever visible per-IP.
func unknownEmailSpray(ctx context.Context) {
	fmt.Println("\n— the same spray against addresses with no account")
	r, err := newRig(ctx, true)
	check("engine constructed", err)
	if r == nil {
		return
	}

	for i := 1; i <= thresholds.TargetAccounts; i++ {
		checkExpectError(fmt.Sprintf("attempt against %s rejected", unknownEmail(i)),
			r.login(ctx, unknownEmail(i), leakedPassword, sprayIP))
	}
	expectSignals(ctx, r, "an unknown-address spray is flagged, and qualified",
		"account_spray,unknown_account_spray")

	events := r.events(ctx)
	if len(events) == 1 {
		expectMeta("unknown targets counted as attempts", events[0], "unknown_targets", "5")
		expectMeta("no real account was named", events[0], "distinct_accounts", "0")
		// The event is about the address; no account owns it.
		expectString("the event has no user to attribute to", events[0].UserID, "")
	}
}

// The case that is deliberately not a spray, and the reason breadth is
// counted in distinct targets rather than attempts: one account hammered
// is what LockoutThreshold and item 8's per-account velocity signal
// already cover.
func oneAccountHammered(ctx context.Context) {
	fmt.Println("\n— many failures against ONE account is not a spray")
	r, err := newRig(ctx, true)
	check("engine constructed", err)
	if r == nil {
		return
	}

	const attempts = 12
	for i := 0; i < attempts; i++ {
		checkExpectError(fmt.Sprintf("wrong password rejected (%d/%d)", i+1, attempts),
			r.login(ctx, email, leakedPassword, sprayIP))
	}
	expectSignals(ctx, r, "twelve failures against one account raise no spray signal")

	since := time.Now().Add(-thresholds.Window)
	counts, err := r.anomalies.CountTargetsForIP(ctx, sprayIP, since)
	check("per-IP breadth read back", err)
	expectCount("volume is high but breadth is one", counts.DistinctAccounts, 1)
	failed, err := r.anomalies.CountFailuresForIP(ctx, sprayIP, since)
	check("per-IP failure count read back", err)
	expectCount("all twelve attempts were recorded", failed, attempts)

	check("the account was never locked and still logs in", r.login(ctx, email, password, knownIP))
}

// The most valuable case in the feature: a login that SUCCEEDS from an
// address currently spraying means one of the guesses landed.
func successFromASprayingIP(ctx context.Context) {
	fmt.Println("\n— a login that succeeds from a spraying address")
	r, err := newRig(ctx, true)
	check("engine constructed", err)
	if r == nil {
		return
	}

	for i := 1; i <= thresholds.TargetAccounts; i++ {
		checkExpectError(fmt.Sprintf("attempt against %s rejected", unknownEmail(i)),
			r.login(ctx, unknownEmail(i), leakedPassword, sprayIP))
	}
	expectSignals(ctx, r, "the spray itself is flagged", "account_spray,unknown_account_spray")

	tokens, err := cryden.Login(ctx, r.engine, email, password, sprayIP, knownAgent)
	check("the real password still logs in from that address", err)
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		fail("expected a full token pair — detection is report-only")
	} else {
		pass("tokens were issued: detection never blocks a login")
	}

	events := r.events(ctx)
	expectCount("the successful login is flagged too", len(events), 2)
	if len(events) == 2 {
		expectString("the second event names the account that got in", events[1].UserID, r.userID)
	}
}

// Without suppression a sustained spray writes one audit event per
// attempt — thousands of identical records describing one incident.
func cooldown(ctx context.Context) {
	fmt.Println("\n— cooldown collapses a sustained spray into one event")
	th := thresholds
	th.Cooldown = 15 * time.Minute
	r, err := newRigWith(ctx, true, th)
	check("engine constructed with a 15m cooldown", err)
	if r == nil {
		return
	}

	for i := 1; i <= 12; i++ {
		checkExpectError(fmt.Sprintf("attempt against %s rejected", unknownEmail(i)),
			r.login(ctx, unknownEmail(i), leakedPassword, sprayIP))
	}
	expectCount("eight crossings, one event", len(r.events(ctx)), 1)

	// A second address is its own incident, not a repeat of the first.
	for i := 1; i <= thresholds.TargetAccounts; i++ {
		checkExpectError(fmt.Sprintf("attempt from a second address against %s rejected", unknownEmail(i)),
			r.login(ctx, unknownEmail(i), leakedPassword, "198.51.100.7"))
	}
	expectCount("a different address is flagged on its own", len(r.events(ctx)), 2)
}

// The feature must be entirely absent until a store is injected — same
// contract as TOTP, WebAuthn and recovery codes.
func detectionOff(ctx context.Context) {
	fmt.Println("\n— detection off (no AnomalyStore configured)")
	r, err := newRig(ctx, false)
	check("engine constructed without an AnomalyStore", err)
	if r == nil {
		return
	}

	for i := 1; i <= 8; i++ {
		checkExpectError(fmt.Sprintf("attempt against %s rejected", unknownEmail(i)),
			r.login(ctx, unknownEmail(i), leakedPassword, sprayIP))
	}
	check("the real account still logs in", r.login(ctx, email, password, sprayIP))
	expectSignals(ctx, r, "nothing is flagged and nothing is recorded")

	counts, err := r.anomalies.CountTargetsForIP(ctx, sprayIP, time.Now().Add(-thresholds.Window))
	check("the unwired store is readable", err)
	expectCount("the unwired store received no attempts", counts.UnknownTargetFailures, 0)
}

// The per-feature off switch: a zero TargetAccounts silences credential
// stuffing while leaving item 8's per-account detection running. The two
// threshold structs are separate precisely so this is possible.
func silencedIndependently(ctx context.Context) {
	fmt.Println("\n— TargetAccounts=0 silences only this feature")
	r, err := newRigWith(ctx, true, security.CredentialStuffingThresholds{})
	check("engine constructed with credential stuffing silenced", err)
	if r == nil {
		return
	}

	for i := 1; i <= anomalyThresholds.IPFailureVelocity; i++ {
		checkExpectError(fmt.Sprintf("attempt against %s rejected", unknownEmail(i)),
			r.login(ctx, unknownEmail(i), leakedPassword, sprayIP))
	}
	check("the real account logs in from the noisy address", r.login(ctx, email, password, sprayIP))

	expectSignals(ctx, r, "no spray event is recorded")
	anomalies, err := r.audit.SearchByType(ctx, store.EventAnomalyDetected, 200)
	check("anomaly events read back", err)
	if len(anomalies) == 0 {
		fail("silencing credential stuffing must not disable anomaly detection")
	} else {
		pass("anomaly detection still fired: " + anomalies[0].Metadata["signals"])
	}
}

// expectSignals asserts the full chronological list of flagged addresses
// so far, which catches a missing signal and an extra one equally.
func expectSignals(ctx context.Context, r *rig, step string, want ...string) {
	got := r.signals(ctx)
	if len(got) != len(want) {
		fail(fmt.Sprintf("%s: expected %d flagged attempt(s) %v, got %d %v",
			step, len(want), want, len(got), got))
		return
	}
	for i := range want {
		if got[i] != want[i] {
			fail(fmt.Sprintf("%s: flagged attempt %d was %q, want %q", step, i+1, got[i], want[i]))
			return
		}
	}
	pass(step)
}

func expectMeta(step string, e store.AuditEvent, key, want string) {
	expectString(step, e.Metadata[key], want)
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

func check(step string, err error) {
	if err != nil {
		fail(fmt.Sprintf("%s: unexpected error: %v", step, err))
		return
	}
	pass(step)
}

func checkExpectError(step string, err error) {
	if err == nil {
		fail(fmt.Sprintf("%s: expected an error, got nil", step))
		return
	}
	pass(fmt.Sprintf("%s (%v)", step, err))
}

func pass(step string) {
	fmt.Println("✓", step)
}

func fail(msg string) {
	failures++
	fmt.Println("✗", msg)
}
