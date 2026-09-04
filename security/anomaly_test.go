package security

import (
	"testing"
	"time"
)

// testThresholds is deliberately not DefaultAnomalyThresholds: these
// tests are about the arithmetic, and hardcoding the numbers they
// depend on means changing a default never silently changes what a
// test asserts.
var testThresholds = AnomalyThresholds{
	Window:                15 * time.Minute,
	HistorySize:           20,
	UserFailureVelocity:   5,
	IPFailureVelocity:     20,
	MaxConcurrentSessions: 10,
	TokenReuseLookback:    24 * time.Hour,
}

func hasSignal(signals []AnomalySignal, want AnomalySignal) bool {
	for _, s := range signals {
		if s == want {
			return true
		}
	}
	return false
}

func TestEvaluate_CleanAttemptReturnsNoSignals(t *testing.T) {
	attempt := LoginAttemptContext{IP: "1.2.3.4", UserAgent: "test-agent"}
	obs := AnomalyObservations{
		KnownIPs:        []string{"1.2.3.4"},
		KnownUserAgents: []string{"test-agent"},
		HasLoginHistory: true,
		ActiveSessions:  2,
	}

	if signals := testThresholds.Evaluate(attempt, obs); len(signals) != 0 {
		t.Fatalf("expected no signals for a familiar attempt, got %v", signals)
	}
}

func TestEvaluate_NewIPAndNewDeviceAreIndependent(t *testing.T) {
	obs := AnomalyObservations{
		KnownIPs:        []string{"1.2.3.4"},
		KnownUserAgents: []string{"test-agent"},
		HasLoginHistory: true,
	}

	// Known device, new address — travel.
	signals := testThresholds.Evaluate(LoginAttemptContext{IP: "9.9.9.9", UserAgent: "test-agent"}, obs)
	if !hasSignal(signals, SignalNewIP) || hasSignal(signals, SignalNewDevice) {
		t.Fatalf("known device on a new IP should flag new_ip only, got %v", signals)
	}

	// Known address, new device — more often a real second party.
	signals = testThresholds.Evaluate(LoginAttemptContext{IP: "1.2.3.4", UserAgent: "other-agent"}, obs)
	if !hasSignal(signals, SignalNewDevice) || hasSignal(signals, SignalNewIP) {
		t.Fatalf("new device on a known IP should flag new_device only, got %v", signals)
	}
}

// A first-ever login has no baseline to deviate from. Flagging it would
// mean every new account's first login is an anomaly, which is noise,
// not signal.
func TestEvaluate_FirstLoginSuppressesNewIPAndDevice(t *testing.T) {
	attempt := LoginAttemptContext{IP: "1.2.3.4", UserAgent: "test-agent"}
	obs := AnomalyObservations{HasLoginHistory: false}

	signals := testThresholds.Evaluate(attempt, obs)
	if len(signals) != 0 {
		t.Fatalf("first-ever login should be clean, got %v", signals)
	}
}

// An absent IP or User-Agent means the caller didn't supply one. Reading
// "" as an unknown device would flag every such attempt forever.
func TestEvaluate_EmptyAttemptFieldsAreNotEvidence(t *testing.T) {
	obs := AnomalyObservations{
		KnownIPs:        []string{"1.2.3.4"},
		KnownUserAgents: []string{"test-agent"},
		HasLoginHistory: true,
	}

	if signals := testThresholds.Evaluate(LoginAttemptContext{}, obs); len(signals) != 0 {
		t.Fatalf("empty IP and User-Agent should produce no signals, got %v", signals)
	}
}

func TestEvaluate_FailureVelocityFiresAtThreshold(t *testing.T) {
	attempt := LoginAttemptContext{IP: "1.2.3.4", UserAgent: "test-agent"}
	base := AnomalyObservations{HasLoginHistory: false}

	cases := []struct {
		name  string
		obs   AnomalyObservations
		want  AnomalySignal
		fires bool
	}{
		{"user one below", AnomalyObservations{RecentUserFailures: 4}, SignalUserFailureVelocity, false},
		{"user at threshold", AnomalyObservations{RecentUserFailures: 5}, SignalUserFailureVelocity, true},
		{"user above", AnomalyObservations{RecentUserFailures: 50}, SignalUserFailureVelocity, true},
		{"ip one below", AnomalyObservations{RecentIPFailures: 19}, SignalIPFailureVelocity, false},
		{"ip at threshold", AnomalyObservations{RecentIPFailures: 20}, SignalIPFailureVelocity, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs := tc.obs
			obs.HasLoginHistory = base.HasLoginHistory
			got := hasSignal(testThresholds.Evaluate(attempt, obs), tc.want)
			if got != tc.fires {
				t.Fatalf("%s fired=%v, want %v", tc.want, got, tc.fires)
			}
		})
	}
}

// The per-IP threshold has to sit well above the per-user one: one
// office NAT legitimately produces many users' typos from one address.
func TestEvaluate_PerIPThresholdIsLooserThanPerUser(t *testing.T) {
	if testThresholds.IPFailureVelocity <= testThresholds.UserFailureVelocity {
		t.Fatalf("IP threshold %d must exceed user threshold %d",
			testThresholds.IPFailureVelocity, testThresholds.UserFailureVelocity)
	}
	if DefaultAnomalyThresholds.IPFailureVelocity <= DefaultAnomalyThresholds.UserFailureVelocity {
		t.Fatal("DefaultAnomalyThresholds must keep the per-IP threshold looser")
	}
}

func TestEvaluate_TokenReuseFiresOnAnyEvent(t *testing.T) {
	attempt := LoginAttemptContext{IP: "1.2.3.4", UserAgent: "test-agent"}

	obs := AnomalyObservations{RecentTokenReuseEvents: 1}
	if !hasSignal(testThresholds.Evaluate(attempt, obs), SignalTokenReuse) {
		t.Fatal("a single token-reuse event should fire token_reuse")
	}

	obs = AnomalyObservations{RecentTokenReuseEvents: 0}
	if hasSignal(testThresholds.Evaluate(attempt, obs), SignalTokenReuse) {
		t.Fatal("no token-reuse history should not fire token_reuse")
	}
}

func TestEvaluate_ConcurrentSessionsFiresOnlyAboveLimit(t *testing.T) {
	attempt := LoginAttemptContext{IP: "1.2.3.4", UserAgent: "test-agent"}

	// At the limit is still allowed — MaxConcurrentSessions is how many
	// a user may hold, not the first flagged count.
	obs := AnomalyObservations{ActiveSessions: 10}
	if hasSignal(testThresholds.Evaluate(attempt, obs), SignalConcurrentSessions) {
		t.Fatal("holding exactly MaxConcurrentSessions should not fire")
	}

	obs = AnomalyObservations{ActiveSessions: 11}
	if !hasSignal(testThresholds.Evaluate(attempt, obs), SignalConcurrentSessions) {
		t.Fatal("exceeding MaxConcurrentSessions should fire concurrent_sessions")
	}
}

// Zeroed thresholds are how a host app turns individual signals off.
func TestEvaluate_ZeroThresholdsDisableTheirSignals(t *testing.T) {
	off := AnomalyThresholds{Window: 15 * time.Minute, HistorySize: 20}
	attempt := LoginAttemptContext{IP: "1.2.3.4", UserAgent: "test-agent"}
	obs := AnomalyObservations{
		RecentUserFailures: 500,
		RecentIPFailures:   500,
		ActiveSessions:     500,
	}

	if signals := off.Evaluate(attempt, obs); len(signals) != 0 {
		t.Fatalf("zeroed thresholds should disable their signals, got %v", signals)
	}
}

// Signal order is part of the contract: the joined string ends up in an
// audit event's metadata, where a host app's monitoring matches on it.
func TestEvaluate_SignalOrderIsStable(t *testing.T) {
	attempt := LoginAttemptContext{IP: "9.9.9.9", UserAgent: "other-agent"}
	obs := AnomalyObservations{
		KnownIPs:               []string{"1.2.3.4"},
		KnownUserAgents:        []string{"test-agent"},
		HasLoginHistory:        true,
		RecentUserFailures:     5,
		RecentIPFailures:       20,
		RecentTokenReuseEvents: 1,
		ActiveSessions:         11,
	}

	want := []AnomalySignal{
		SignalNewIP,
		SignalNewDevice,
		SignalUserFailureVelocity,
		SignalIPFailureVelocity,
		SignalTokenReuse,
		SignalConcurrentSessions,
	}

	got := testThresholds.Evaluate(attempt, obs)
	if len(got) != len(want) {
		t.Fatalf("expected all %d signals, got %v", len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("signal %d = %s, want %s (full: %v)", i, got[i], want[i], got)
		}
	}

	const expected = "new_ip,new_device,user_failure_velocity,ip_failure_velocity,token_reuse,concurrent_sessions"
	if joined := JoinAnomalySignals(got); joined != expected {
		t.Fatalf("JoinAnomalySignals = %q, want %q", joined, expected)
	}
}

func TestJoinAnomalySignals_EmptyIsEmptyString(t *testing.T) {
	if joined := JoinAnomalySignals(nil); joined != "" {
		t.Fatalf("expected empty string for no signals, got %q", joined)
	}
}

// The whole-struct zero comparison in Config.applyDefaults only works
// while AnomalyThresholds stays comparable (no slices or maps).
func TestAnomalyThresholds_IsComparable(t *testing.T) {
	if (AnomalyThresholds{}) == DefaultAnomalyThresholds {
		t.Fatal("the zero value must differ from the defaults, or defaulting is a no-op")
	}
}
