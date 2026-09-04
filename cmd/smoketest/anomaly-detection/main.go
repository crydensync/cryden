// Command anomaly-detection is a standalone, no-database smoke test for
// login anomaly detection: new-IP/new-device signals, per-user and
// per-IP failure velocity, token-reuse history, concurrent sessions,
// and — the property the whole feature rests on — that a flagged login
// still succeeds. Run with:
//
//	go run ./cmd/smoketest/anomaly-detection
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
)

const (
	email    = "raymondproguy@dev.com"
	password = "Tr0ubl3-Fr33!2026"

	knownIP     = "1.2.3.4"
	knownAgent  = "cryden-smoketest/1.0"
	strangeIP   = "203.0.113.9"
	otherAgent  = "unknown-browser/9.9"
	wrongPass   = "not-the-password"
	unknownMail = "nobody@dev.com"
)

// Small numbers so a burst is a handful of calls, not twenty.
var thresholds = security.AnomalyThresholds{
	Window:                15 * time.Minute,
	HistorySize:           20,
	UserFailureVelocity:   3,
	IPFailureVelocity:     5,
	MaxConcurrentSessions: 50,
	TokenReuseLookback:    24 * time.Hour,
}

var failures int

// rig is one isolated engine plus the two stores the checks read back
// from. Each scenario gets a fresh one so signal counts never bleed
// between them.
type rig struct {
	engine    *cryden.Engine
	audit     *memory.AuditStore
	anomalies *memory.AnomalyStore
	userID    string
}

func newRig(ctx context.Context, detectionOn bool) (*rig, error) {
	return newRigWith(ctx, detectionOn, thresholds)
}

func newRigWith(ctx context.Context, detectionOn bool, th security.AnomalyThresholds) (*rig, error) {
	r := &rig{
		audit:     memory.NewAuditStore(),
		anomalies: memory.NewAnomalyStore(),
	}
	cfg := cryden.Config{
		JWTSecret:         "smoketest-jwt-secret",
		Users:             memory.NewUserStore(),
		Sessions:          memory.NewSessionStore(),
		Audit:             r.audit,
		AnomalyThresholds: th,
		// High enough that lockout never fires first and masks a
		// velocity signal — this smoke test is about detection, and
		// lockout is a separate, already-shipped feature.
		LockoutThreshold: 100,
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

// login runs a real password login and reports whether it succeeded.
func (r *rig) login(ctx context.Context, ip, agent, pass string) error {
	_, err := cryden.Login(ctx, r.engine, email, pass, ip, agent)
	return err
}

// signals returns the "signals" metadata of every anomaly event
// recorded so far, oldest first.
func (r *rig) signals(ctx context.Context) []string {
	events, err := r.audit.ListByUser(ctx, r.userID, 200)
	if err != nil {
		fail(fmt.Sprintf("reading audit events: %v", err))
		return nil
	}
	var out []string
	// ListByUser is newest-first; walk backwards for chronological order.
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Type == store.EventAnomalyDetected {
			out = append(out, events[i].Metadata["signals"])
		}
	}
	return out
}

func main() {
	ctx := context.Background()

	newIPAndDevice(ctx)
	userFailureVelocity(ctx)
	ipFailureVelocity(ctx)
	tokenReuse(ctx)
	concurrentSessions(ctx)
	detectionOff(ctx)

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
		return
	}
	fmt.Printf("%d CHECK(S) FAILED\n", failures)
	os.Exit(1)
}

func newIPAndDevice(ctx context.Context) {
	fmt.Println("— new IP and new device")
	r, err := newRig(ctx, true)
	check("engine constructed with an AnomalyStore", err)
	if r == nil {
		return
	}

	// A first-ever login has no baseline to deviate from. Flagging it
	// would mean flagging every new account's first login.
	check("first login succeeds", r.login(ctx, knownIP, knownAgent, password))
	expectSignals(ctx, r, "first login is not flagged")

	check("second login from the same IP and device succeeds", r.login(ctx, knownIP, knownAgent, password))
	expectSignals(ctx, r, "a familiar login stays quiet")

	// The load-bearing negative case: flagged, and still logged in.
	check("login from an unknown IP and device succeeds anyway",
		r.login(ctx, strangeIP, otherAgent, password))
	expectSignals(ctx, r, "unfamiliar IP and device are both flagged", "new_ip,new_device")

	// Known device, new address — travel, not a second party.
	check("login from another new IP on the known device succeeds",
		r.login(ctx, "198.51.100.7", knownAgent, password))
	expectSignals(ctx, r, "a known device on a new IP flags new_ip only",
		"new_ip,new_device", "new_ip")

	// The address from the flagged login is now part of the baseline.
	check("repeat login from the previously-unknown IP succeeds",
		r.login(ctx, strangeIP, otherAgent, password))
	expectSignals(ctx, r, "a now-familiar IP and device stop flagging",
		"new_ip,new_device", "new_ip")
}

func userFailureVelocity(ctx context.Context) {
	fmt.Println("\n— per-user failure velocity")
	r, err := newRig(ctx, true)
	check("engine constructed", err)
	if r == nil {
		return
	}

	// Baseline first, so only the velocity signal can fire on the
	// recovering login.
	check("baseline login succeeds", r.login(ctx, knownIP, knownAgent, password))

	for i := 0; i < thresholds.UserFailureVelocity; i++ {
		checkExpectError(fmt.Sprintf("wrong password rejected (%d/%d)", i+1, thresholds.UserFailureVelocity),
			r.login(ctx, knownIP, knownAgent, wrongPass))
	}

	count, err := r.anomalies.CountFailuresForUser(ctx, r.userID, time.Now().Add(-thresholds.Window))
	check("failed attempts are recorded for the account", err)
	expectCount("recorded failures match the burst", count, thresholds.UserFailureVelocity)

	check("the correct password still works after the burst",
		r.login(ctx, knownIP, knownAgent, password))
	expectSignals(ctx, r, "the recovering login is flagged for velocity", "user_failure_velocity")
}

func ipFailureVelocity(ctx context.Context) {
	fmt.Println("\n— per-IP failure velocity, across accounts")
	r, err := newRig(ctx, true)
	check("engine constructed", err)
	if r == nil {
		return
	}

	check("baseline login succeeds", r.login(ctx, knownIP, knownAgent, password))

	// Attempts against an address with no account behind it. These carry
	// no user ID, so they can only be counted per-IP — which is the
	// shape of a spray across many accounts from one source.
	for i := 0; i < thresholds.IPFailureVelocity; i++ {
		_, err := cryden.Login(ctx, r.engine, unknownMail, wrongPass, knownIP, knownAgent)
		checkExpectError(fmt.Sprintf("attempt against a nonexistent account rejected (%d/%d)",
			i+1, thresholds.IPFailureVelocity), err)
	}

	since := time.Now().Add(-thresholds.Window)
	ipCount, err := r.anomalies.CountFailuresForIP(ctx, knownIP, since)
	check("failures are counted for the source IP", err)
	expectCount("per-IP count spans accounts that do not exist", ipCount, thresholds.IPFailureVelocity)

	userCount, err := r.anomalies.CountFailuresForUser(ctx, r.userID, since)
	check("per-user count read back", err)
	expectCount("unknown-email failures are not attributed to a real user", userCount, 0)

	check("the real account can still log in", r.login(ctx, knownIP, knownAgent, password))
	expectSignals(ctx, r, "the login from the noisy IP is flagged", "ip_failure_velocity")
}

func tokenReuse(ctx context.Context) {
	fmt.Println("\n— token-reuse history")
	r, err := newRig(ctx, true)
	check("engine constructed", err)
	if r == nil {
		return
	}

	check("baseline login succeeds", r.login(ctx, knownIP, knownAgent, password))

	// Refresh-token reuse already revoked the family when it happened.
	// This records that it did, the way RefreshToken would have.
	err = r.audit.Record(ctx, store.AuditEvent{
		Type:   store.EventTokenReuseDetected,
		UserID: r.userID,
		IP:     strangeIP,
	})
	check("a prior token-reuse detection is on record", err)

	check("login after a reuse incident still succeeds", r.login(ctx, knownIP, knownAgent, password))
	expectSignals(ctx, r, "the login is visibly connected to the reuse incident", "token_reuse")
}

func concurrentSessions(ctx context.Context) {
	fmt.Println("\n— concurrent sessions")
	sessionLimited := thresholds
	sessionLimited.MaxConcurrentSessions = 2
	r, err := newRigWith(ctx, true, sessionLimited)
	check("engine constructed with a 2-session limit", err)
	if r == nil {
		return
	}

	// Observations are read before this attempt's own session exists, so
	// login N sees N-1 active sessions. With a limit of 2, the fourth
	// login is the first to observe 3.
	for i := 0; i < 3; i++ {
		check(fmt.Sprintf("login %d of 3 succeeds", i+1), r.login(ctx, knownIP, knownAgent, password))
	}
	expectSignals(ctx, r, "holding up to the session limit is not flagged")

	check("login past the session limit succeeds", r.login(ctx, knownIP, knownAgent, password))
	expectSignals(ctx, r, "exceeding the session limit is flagged", "concurrent_sessions")

	sessions, err := cryden.ListSessions(ctx, r.engine, r.userID)
	check("sessions read back", err)
	expectCount("no session was revoked by the flag", len(sessions), 4)
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

	check("login from a known IP succeeds", r.login(ctx, knownIP, knownAgent, password))
	check("login from an unknown IP and device succeeds", r.login(ctx, strangeIP, otherAgent, password))
	checkExpectError("wrong password still rejected", r.login(ctx, knownIP, knownAgent, wrongPass))
	expectSignals(ctx, r, "nothing is flagged and nothing is recorded")

	count, err := r.anomalies.CountFailuresForUser(ctx, r.userID, time.Now().Add(-thresholds.Window))
	check("the unwired store is readable", err)
	expectCount("the unwired store received no attempts", count, 0)
}

// expectSignals asserts the full chronological list of flagged logins so
// far, which catches a missing signal and an extra one equally.
func expectSignals(ctx context.Context, r *rig, step string, want ...string) {
	got := r.signals(ctx)
	if len(got) != len(want) {
		fail(fmt.Sprintf("%s: expected %d flagged login(s) %v, got %d %v",
			step, len(want), want, len(got), got))
		return
	}
	for i := range want {
		if got[i] != want[i] {
			fail(fmt.Sprintf("%s: flagged login %d was %q, want %q", step, i+1, got[i], want[i]))
			return
		}
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
