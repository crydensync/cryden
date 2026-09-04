package security

import (
	"strings"
	"time"
)

// AnomalySignal is one machine-readable reason a login attempt looked
// unusual. Like PasswordPolicy's violation codes, these are stable
// short strings rather than human sentences — the engine doesn't own UI
// copy or localization anywhere else, and these end up in an audit
// event's metadata for a host app's monitoring to match on, not in
// front of a user.
type AnomalySignal string

const (
	// SignalNewIP fires when the attempt's IP has not appeared in the
	// user's recent successful logins.
	SignalNewIP AnomalySignal = "new_ip"
	// SignalNewDevice fires when the attempt's User-Agent has not
	// appeared in the user's recent successful logins. Separate from
	// SignalNewIP because they mean genuinely different things — a
	// known device on a new IP is travel, a new device on a known IP
	// is more often a real second party.
	SignalNewDevice AnomalySignal = "new_device"
	// SignalUserFailureVelocity fires when this one account has
	// accumulated failed attempts faster than AnomalyThresholds allows.
	SignalUserFailureVelocity AnomalySignal = "user_failure_velocity"
	// SignalIPFailureVelocity fires when this one IP has accumulated
	// failed attempts faster than AnomalyThresholds allows, counting
	// across every account it targeted.
	SignalIPFailureVelocity AnomalySignal = "ip_failure_velocity"
	// SignalTokenReuse fires when the user has recent
	// store.EventTokenReuseDetected history. Refresh-token reuse
	// already revokes the whole session family when it happens; this
	// signal exists so a login arriving shortly afterward is visibly
	// connected to it instead of looking routine.
	SignalTokenReuse AnomalySignal = "token_reuse"
	// SignalConcurrentSessions fires when the user holds more active
	// sessions than AnomalyThresholds allows.
	SignalConcurrentSessions AnomalySignal = "concurrent_sessions"
)

// LoginAttemptContext is what the detector knows about the attempt
// being evaluated right now. Deliberately not store.Session or
// store.LoginAttempt — Evaluate is pure logic in a package that has no
// storage dependency, so it takes plain values.
type LoginAttemptContext struct {
	IP        string
	UserAgent string
}

// AnomalyObservations is the history snapshot Evaluate judges an
// attempt against — the whole storage-facing side of detection reduced
// to plain numbers and strings. Whoever gathers this (see
// auth.DetectLoginAnomalies) owns the queries; Evaluate never reads
// anything itself, which is what makes the thresholds testable without
// a store at all.
type AnomalyObservations struct {
	// KnownIPs and KnownUserAgents come from the user's recent
	// SUCCESSFUL logins only. A failed attempt from an IP must never
	// teach the baseline that the IP is familiar — otherwise an
	// attacker establishes their own trust just by failing a few times
	// first.
	KnownIPs        []string
	KnownUserAgents []string
	// HasLoginHistory reports whether the user has any prior successful
	// login at all. Without it, every account's first-ever login trips
	// both new_ip and new_device, which is pure noise — there is no
	// baseline yet to deviate from.
	HasLoginHistory bool
	// RecentUserFailures and RecentIPFailures are counted over
	// AnomalyThresholds.Window.
	RecentUserFailures int
	RecentIPFailures   int
	// RecentTokenReuseEvents counts store.EventTokenReuseDetected
	// events for this user.
	RecentTokenReuseEvents int
	// ActiveSessions is the user's current non-revoked session count.
	ActiveSessions int
}

// AnomalyThresholds tunes which observations count as anomalous. Plain
// configuration data with a method, same shape as PasswordPolicy — the
// swappable part of this feature is the store the observations come
// from, not the arithmetic here.
type AnomalyThresholds struct {
	// Window bounds the failure-velocity counts. Defaults to 15
	// minutes when the whole struct is left zero-valued (see
	// Config.applyDefaults).
	Window time.Duration
	// HistorySize is how many recent successful logins form the
	// known-IP/known-device baseline. Too small and normal multi-device
	// users trip new_device constantly; too large and a long-abandoned
	// device stays trusted forever.
	HistorySize int
	// UserFailureVelocity is the failed-attempt count for ONE account
	// within Window that flags the attempt. Defaults to 5, matching
	// Config.LockoutThreshold's default — an account that just came off
	// (or is riding the edge of) lockout is exactly the case worth
	// surfacing.
	UserFailureVelocity int
	// IPFailureVelocity is the failed-attempt count from ONE IP within
	// Window that flags the attempt, counted across every account that
	// IP targeted. Deliberately much higher than
	// UserFailureVelocity: one office NAT or mobile carrier gateway
	// legitimately produces many users' typos from a single address.
	IPFailureVelocity int
	// MaxConcurrentSessions is the active-session count a user may hold
	// before the next login is flagged. Zero disables the check.
	MaxConcurrentSessions int
	// TokenReuseLookback bounds how far back a
	// store.EventTokenReuseDetected event still counts. Separate from
	// Window, and much longer, because the two signals live on
	// different time scales: failure velocity is about a burst happening
	// right now, while a stolen refresh token replayed this morning is
	// still the most relevant thing about a login this afternoon.
	// Unbounded would be wrong too — one reuse event would then flag
	// every login the account ever makes again.
	TokenReuseLookback time.Duration
}

// DefaultAnomalyThresholds is applied whenever Config.AnomalyThresholds
// is left as the zero value. Unlike DefaultPasswordPolicy this is not a
// security floor — anomaly detection as a whole is off until
// Config.Anomalies is set, and these numbers only decide how chatty it
// is once it's on.
var DefaultAnomalyThresholds = AnomalyThresholds{
	Window:                15 * time.Minute,
	HistorySize:           20,
	UserFailureVelocity:   5,
	IPFailureVelocity:     20,
	MaxConcurrentSessions: 10,
	TokenReuseLookback:    24 * time.Hour,
}

// Evaluate returns every signal the attempt trips, in a stable order,
// or nil for a clean attempt. It reports; it never decides. Nothing
// here blocks a login, returns a sentinel error, or forces step-up
// authentication — a flagged attempt is recorded and handed to the host
// app, which owns what to do about it. False positives are expected
// (travel, a new browser, a shared office IP), and locking real users
// out over them would be a worse outcome than the detection is worth.
func (t AnomalyThresholds) Evaluate(attempt LoginAttemptContext, obs AnomalyObservations) []AnomalySignal {
	var signals []AnomalySignal

	// An empty IP or User-Agent isn't evidence of anything — the caller
	// simply didn't supply one. Silently treating "" as an unknown
	// device would flag every such attempt forever.
	if obs.HasLoginHistory {
		if attempt.IP != "" && !containsString(obs.KnownIPs, attempt.IP) {
			signals = append(signals, SignalNewIP)
		}
		if attempt.UserAgent != "" && !containsString(obs.KnownUserAgents, attempt.UserAgent) {
			signals = append(signals, SignalNewDevice)
		}
	}

	if t.UserFailureVelocity > 0 && obs.RecentUserFailures >= t.UserFailureVelocity {
		signals = append(signals, SignalUserFailureVelocity)
	}
	if t.IPFailureVelocity > 0 && obs.RecentIPFailures >= t.IPFailureVelocity {
		signals = append(signals, SignalIPFailureVelocity)
	}
	if obs.RecentTokenReuseEvents > 0 {
		signals = append(signals, SignalTokenReuse)
	}
	if t.MaxConcurrentSessions > 0 && obs.ActiveSessions > t.MaxConcurrentSessions {
		signals = append(signals, SignalConcurrentSessions)
	}

	return signals
}

// JoinAnomalySignals renders signals as one comma-separated string, for
// an audit event's metadata (which is map[string]string — no room for a
// list). Order matches Evaluate's, so the value is stable enough for a
// host app's monitoring to match on.
func JoinAnomalySignals(signals []AnomalySignal) string {
	parts := make([]string, len(signals))
	for i, s := range signals {
		parts[i] = string(s)
	}
	return strings.Join(parts, ",")
}

func containsString(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
