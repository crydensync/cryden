package security

import (
	"testing"
	"time"
)

// testStuffingThresholds, like testThresholds above it, deliberately
// hardcodes its numbers instead of using
// DefaultCredentialStuffingThresholds — these tests are about the
// arithmetic, and a tuning change to a default should never silently
// change what they assert.
var testStuffingThresholds = CredentialStuffingThresholds{
	Window:         time.Hour,
	TargetAccounts: 10,
	Cooldown:       15 * time.Minute,
}

func TestStuffingEvaluate_BreadthBelowThresholdIsClean(t *testing.T) {
	// Nine targets against a threshold of ten. A busy office NAT looks
	// exactly like this and must not be flagged.
	obs := CredentialStuffingObservations{DistinctAccounts: 4, UnknownTargetFailures: 5}

	if signals := testStuffingThresholds.Evaluate(obs); len(signals) != 0 {
		t.Fatalf("expected no signals below the threshold, got %v", signals)
	}
}

func TestStuffingEvaluate_ThresholdIsInclusive(t *testing.T) {
	// The tenth target trips a threshold of ten, not the eleventh —
	// the detector in package auth relies on this, since it evaluates
	// after recording the attempt that just happened.
	obs := CredentialStuffingObservations{DistinctAccounts: 10}

	signals := testStuffingThresholds.Evaluate(obs)
	if !hasSignal(signals, SignalAccountSpray) {
		t.Fatalf("expected account_spray at exactly the threshold, got %v", signals)
	}
}

func TestStuffingEvaluate_KnownAndUnknownTargetsAreAddedTogether(t *testing.T) {
	// The case a second, separate unknown-email threshold would miss:
	// six real accounts and five nonexistent ones clears no single
	// population's bar, but eleven targets from one address in an hour
	// is the attack this feature exists to see.
	obs := CredentialStuffingObservations{DistinctAccounts: 6, UnknownTargetFailures: 5}

	if obs.Breadth() != 11 {
		t.Fatalf("expected breadth 11, got %d", obs.Breadth())
	}
	if signals := testStuffingThresholds.Evaluate(obs); !hasSignal(signals, SignalAccountSpray) {
		t.Fatalf("expected a mixed spray to flag, got %v", signals)
	}
}

func TestStuffingEvaluate_KnownOnlySprayOmitsUnknownQualifier(t *testing.T) {
	// Every target exists here, which says the attacker knows this
	// system's user list — a materially different situation from a
	// blind list, so the qualifier must stay off.
	obs := CredentialStuffingObservations{DistinctAccounts: 12}

	signals := testStuffingThresholds.Evaluate(obs)
	if !hasSignal(signals, SignalAccountSpray) {
		t.Fatalf("expected account_spray, got %v", signals)
	}
	if hasSignal(signals, SignalUnknownAccountSpray) {
		t.Fatalf("no unknown targets, so the qualifier must not fire: %v", signals)
	}
}

func TestStuffingEvaluate_UnknownHeavySprayAddsQualifier(t *testing.T) {
	// A list from somewhere else, tried blind: two of the addresses
	// happen to exist here, the other eighteen never did.
	obs := CredentialStuffingObservations{DistinctAccounts: 2, UnknownTargetFailures: 18}

	signals := testStuffingThresholds.Evaluate(obs)
	if !hasSignal(signals, SignalAccountSpray) || !hasSignal(signals, SignalUnknownAccountSpray) {
		t.Fatalf("expected both account_spray and unknown_account_spray, got %v", signals)
	}
	// Order is stable so JoinAnomalySignals produces a value a host
	// app's monitoring can match on.
	if signals[0] != SignalAccountSpray {
		t.Fatalf("expected account_spray first, got %v", signals)
	}
}

func TestStuffingEvaluate_EvenSplitIsNotCalledUnknownHeavy(t *testing.T) {
	// Strictly greater, not >=: a spray split down the middle is not
	// "mostly against addresses that don't exist here."
	obs := CredentialStuffingObservations{DistinctAccounts: 6, UnknownTargetFailures: 6}

	signals := testStuffingThresholds.Evaluate(obs)
	if !hasSignal(signals, SignalAccountSpray) {
		t.Fatalf("expected account_spray, got %v", signals)
	}
	if hasSignal(signals, SignalUnknownAccountSpray) {
		t.Fatalf("an even split must not be described as unknown-heavy: %v", signals)
	}
}

func TestStuffingEvaluate_ZeroTargetAccountsIsAnOffSwitch(t *testing.T) {
	// The documented way to run anomaly detection with this one signal
	// silenced, since both features share Config.Anomalies as their
	// on/off switch.
	off := CredentialStuffingThresholds{Window: time.Hour}
	obs := CredentialStuffingObservations{DistinctAccounts: 500, UnknownTargetFailures: 5000}

	if signals := off.Evaluate(obs); len(signals) != 0 {
		t.Fatalf("a zero TargetAccounts must disable detection, got %v", signals)
	}
}

func TestStuffingEvaluate_NegativeTargetAccountsIsAlsoOff(t *testing.T) {
	// A negative threshold is a misconfiguration, and the only safe
	// reading of it is "off" — treating it as "flag everything" would
	// fill a host app's audit trail on the first failed login.
	off := CredentialStuffingThresholds{Window: time.Hour, TargetAccounts: -1}

	if signals := off.Evaluate(CredentialStuffingObservations{}); len(signals) != 0 {
		t.Fatalf("expected no signals, got %v", signals)
	}
}

func TestStuffingSignalsShareTheAnomalySignalRenderer(t *testing.T) {
	// The reason these constants are AnomalySignal values: one joiner
	// serves both features' audit metadata.
	got := JoinAnomalySignals([]AnomalySignal{SignalAccountSpray, SignalUnknownAccountSpray})
	if got != "account_spray,unknown_account_spray" {
		t.Fatalf("unexpected rendering: %q", got)
	}
}

func TestDefaultCredentialStuffingThresholds_IsUsable(t *testing.T) {
	d := DefaultCredentialStuffingThresholds
	if d.Window <= 0 || d.TargetAccounts <= 0 {
		t.Fatalf("the shipped default must actually detect something: %+v", d)
	}
	// Without a cooldown a sustained spray emits one audit event per
	// failed attempt, which is the failure mode the default must not
	// ship with.
	if d.Cooldown <= 0 {
		t.Fatalf("expected a non-zero default cooldown, got %v", d.Cooldown)
	}
	// Longer than the anomaly window: breadth accumulates more slowly
	// than volume.
	if d.Window <= DefaultAnomalyThresholds.Window {
		t.Fatalf("expected a wider window than anomaly detection's %v, got %v", DefaultAnomalyThresholds.Window, d.Window)
	}
}
