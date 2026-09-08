package admin

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// DefaultTuningWindow is how far back a tuning report looks — 30 days
// rather than the digest's 7: a config knob should be judged against a
// month of traffic, not whatever happened to occur this week.
const DefaultTuningWindow = 30 * 24 * time.Hour

// TuningInputs is a snapshot of the engine's current tuning knobs —
// plain data, not a store and not the security package's own config
// structs (deliberately: importing them here would pull this package's
// dependency graph in after security, and BuildTuningReport needs
// exactly six numbers and three booleans out of them, not the structs
// themselves). BuildTuningReport is handed a copy rather than a live
// *Engine so producing a report can never itself depend on anything
// beyond what New() already computed.
type TuningInputs struct {
	LockoutThreshold  int
	LockoutDuration   time.Duration
	RateLimitAttempts int
	RateLimitWindow   time.Duration
	// UsingDefaultRateLimiter is true when no custom security.RateLimiter
	// (e.g. a Redis-backed one) was configured — the in-memory default,
	// which keeps its counters in a single process's memory.
	UsingDefaultRateLimiter bool

	// AnomaliesEnabled is Config.Anomalies != nil — detection runs at
	// all only when this is true; the fields below are meaningless
	// otherwise and BuildTuningReport does not read them in that case.
	AnomaliesEnabled bool
	// UserFailureVelocity, IPFailureVelocity, HistorySize mirror
	// security.AnomalyThresholds' fields of the same name.
	UserFailureVelocity int
	IPFailureVelocity   int
	HistorySize         int
	// StuffingTargetAccounts, StuffingWindow, StuffingCooldown mirror
	// security.CredentialStuffingThresholds' TargetAccounts, Window,
	// Cooldown.
	StuffingTargetAccounts int
	StuffingWindow         time.Duration
	StuffingCooldown       time.Duration

	BreachedPasswordCheckerActive bool
}

// TuningSuggestion is one observation and the change it points at.
// Area names the knob it concerns; Finding is the exact numbers behind
// it; Suggestion is what to consider — never applied by this package or
// anything that calls it.
type TuningSuggestion struct {
	Area       string
	Finding    string
	Suggestion string
}

// TuningReport is BuildTuningReport's result: the window it covers, the
// suggestions it produced (possibly none), and the raw counts they were
// computed from, for a caller that wants the numbers rather than the
// prose.
type TuningReport struct {
	Since       time.Time
	Until       time.Time
	Counts      map[store.AuditEventType]int
	Suggestions []TuningSuggestion
}

// BuildTuningReport reads audit counts over the window ending now and
// starting at since, and turns them — together with in, the engine's
// own current settings — into a list of suggested configuration
// changes. It never applies any of them: there is no write path here at
// all, config or otherwise, the same non-negotiable rule item 19 and
// item 20 both follow. Running this twice in a row against the same
// history produces the same suggestions.
func BuildTuningReport(ctx context.Context, r AuditReader, in TuningInputs, since time.Time) (TuningReport, error) {
	counts, err := r.CountByType(ctx, since)
	if err != nil {
		return TuningReport{}, fmt.Errorf("admin: counting audit events: %w", err)
	}

	report := TuningReport{Since: since.UTC(), Counts: counts}
	report.Suggestions = append(report.Suggestions, lockoutSuggestions(counts, in)...)
	report.Suggestions = append(report.Suggestions, rateLimiterSuggestions(in)...)
	report.Suggestions = append(report.Suggestions, anomalySuggestions(counts, in)...)
	report.Suggestions = append(report.Suggestions, stuffingSuggestions(counts, in)...)
	report.Suggestions = append(report.Suggestions, passwordSuggestions(counts, in)...)

	// Read after the query, matching BuildDigest's own reasoning: so
	// everything the suggestions are based on really did happen at or
	// before the window this report claims to cover.
	report.Until = time.Now().UTC()
	return report, nil
}

// lockoutSuggestions flags a lockout rate that looks like it's mostly
// catching legitimate users rather than attackers. Deliberately
// one-directional: this package has no way to tell a slow, spread-thin
// brute force (which item 9's credential-stuffing detection is the
// actual answer to) from an account nobody has touched in months, so it
// does not guess a lockout threshold is too high from silence alone.
func lockoutSuggestions(counts map[store.AuditEventType]int, in TuningInputs) []TuningSuggestion {
	locked := counts[store.EventAccountLocked]
	failed := counts[store.EventLoginFailed]
	if failed == 0 || locked < 3 {
		return nil
	}
	ratio := float64(locked) / float64(failed)
	if ratio < 0.1 {
		return nil
	}
	return []TuningSuggestion{{
		Area: "Lockout",
		Finding: fmt.Sprintf("%s out of %s recorded in this window (%.0f%%) — LockoutThreshold is currently %d, LockoutDuration %s.",
			pluralize(locked, "account was locked", "accounts were locked"), formatCount(failed), ratio*100, in.LockoutThreshold, in.LockoutDuration),
		Suggestion: "If most of these are real users mistyping a password rather than an attack, consider raising LockoutThreshold and/or shortening LockoutDuration so a genuine user regains access sooner. If they look attack-shaped instead, leave it — this is exactly what the threshold is for.",
	}}
}

// rateLimiterSuggestions repeats a caveat that is already documented on
// Config.RateLimiter itself: the in-memory default is correct for one
// process only. This is the one suggestion here that needs no audit
// data at all — it is a fact about the deployment, not the traffic.
func rateLimiterSuggestions(in TuningInputs) []TuningSuggestion {
	if !in.UsingDefaultRateLimiter {
		return nil
	}
	return []TuningSuggestion{{
		Area:       "Rate limiting",
		Finding:    fmt.Sprintf("Using the default in-memory rate limiter (%d attempts per %s).", in.RateLimitAttempts, in.RateLimitWindow),
		Suggestion: "This keeps its counters in one process's memory. Running more than one instance behind a load balancer means each replica counts independently, so the effective limit is (instances × RateLimitAttempts). If this deployment runs more than one instance, consider security.NewRedisRateLimiter for a shared limiter.",
	}}
}

// anomalySuggestions covers three states: detection off entirely,
// detection on but silent despite real volume, and detection firing on
// a large share of successful sign-ins (which points at thresholds
// tuned tighter than this traffic pattern, not at an actual problem).
func anomalySuggestions(counts map[store.AuditEventType]int, in TuningInputs) []TuningSuggestion {
	if !in.AnomaliesEnabled {
		return []TuningSuggestion{{
			Area:       "Anomaly detection",
			Finding:    "Config.Anomalies is not set, so no login is screened for new-IP, new-device, failure-velocity, or session-count signals.",
			Suggestion: "Report-only and off by default — consider enabling it (a store.AnomalyStore) if this deployment wants that visibility. Nothing about login behavior changes when it's on; a flagged attempt is still let through.",
		}}
	}

	successes := counts[store.EventLoginSuccess]
	flagged := counts[store.EventAnomalyDetected]

	const meaningfulSample = 50
	if flagged == 0 && successes >= meaningfulSample {
		return []TuningSuggestion{{
			Area: "Anomaly detection",
			Finding: fmt.Sprintf("%s recorded in this window, none flagged (UserFailureVelocity=%d, IPFailureVelocity=%d, HistorySize=%d).",
				pluralize(successes, "successful sign-in", "successful sign-ins"),
				in.UserFailureVelocity, in.IPFailureVelocity, in.HistorySize),
			Suggestion: "This may simply reflect a quiet window rather than a problem — not inherently something to change. If this deployment expects to see occasional flags and consistently sees none, the thresholds above may be looser than this traffic pattern.",
		}}
	}

	if successes > 0 && flagged > 0 {
		share := float64(flagged) / float64(successes)
		const highShare = 0.2
		if share >= highShare {
			return []TuningSuggestion{{
				Area: "Anomaly detection",
				Finding: fmt.Sprintf("%s of %s successful sign-ins in this window (%.0f%%) were flagged as anomalous.",
					formatCount(flagged), formatCount(successes), share*100),
				Suggestion: "If most of these represent ordinary behavior for these users (shared office egress, frequent travel, rotating mobile IPs), the thresholds may be tighter than this population needs — consider raising UserFailureVelocity, IPFailureVelocity, or HistorySize. If they look real instead, leave it.",
			}}
		}
	}

	return nil
}

// stuffingSuggestions only has anything to say when detection actually
// fired — a silent window says nothing distinguishable from "anomaly
// detection is also quiet," so there is no separate silence branch here
// the way anomalySuggestions has one.
func stuffingSuggestions(counts map[store.AuditEventType]int, in TuningInputs) []TuningSuggestion {
	if !in.AnomaliesEnabled {
		return nil
	}
	bursts := counts[store.EventCredentialStuffingDetected]
	if bursts == 0 {
		return nil
	}
	return []TuningSuggestion{{
		Area: "Credential stuffing",
		Finding: fmt.Sprintf("%s detected in this window (TargetAccounts=%d over a %s window, %s cooldown).",
			pluralize(bursts, "burst", "bursts"), in.StuffingTargetAccounts,
			in.StuffingWindow, in.StuffingCooldown),
		Suggestion: "If these recur often, consider lowering TargetAccounts or shortening Window to catch a burst earlier. If they consistently trace back to one shared, legitimate address (an office NAT, a corporate VPN egress), consider raising TargetAccounts instead so that address stops tripping it.",
	}}
}

// passwordSuggestions is the only pair of findings here that can be
// good news rather than a problem: a working breach checker rejecting
// real breached passwords is the feature working as intended, not
// something to tune.
func passwordSuggestions(counts map[store.AuditEventType]int, in TuningInputs) []TuningSuggestion {
	if !in.BreachedPasswordCheckerActive {
		return []TuningSuggestion{{
			Area:       "Password strength",
			Finding:    "Config.BreachedPasswordChecker is not set.",
			Suggestion: "Checked only on SignUp/ChangePassword when configured, and fails open on error, so it is a strictly additive protection with no downside to enabling.",
		}}
	}
	rejected := counts[store.EventPasswordBreachRejected]
	if rejected > 0 {
		return []TuningSuggestion{{
			Area:       "Password strength",
			Finding:    fmt.Sprintf("%s in this window.", pluralize(rejected, "password was rejected for appearing in a breach corpus", "passwords were rejected for appearing in a breach corpus")),
			Suggestion: "The checker is actively protecting these accounts. No change suggested.",
		}}
	}
	return nil
}

// Text renders the report as something a human reads: the window, then
// one paragraph per suggestion, in the fixed order BuildTuningReport
// assembled them — lockout first (the knob most likely to be actively
// locking someone out right now), then the rest. A window with nothing
// to suggest says so in one line rather than printing an empty report.
func (r TuningReport) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Config tuning report — %s to %s (%s)\n",
		formatDigestTime(r.Since), formatDigestTime(r.Until), humanWindow(r.Until.Sub(r.Since)))

	if len(r.Suggestions) == 0 {
		b.WriteString("\nNothing stands out against current settings in this window.\n")
		return b.String()
	}

	for _, s := range r.Suggestions {
		fmt.Fprintf(&b, "\n%s\n  %s\n  → %s\n", s.Area, s.Finding, s.Suggestion)
	}
	return b.String()
}
