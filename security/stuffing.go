package security

import "time"

// Credential-stuffing signals are AnomalySignal values rather than
// their own type. The distinction that matters is what they are scoped
// to — one IP's behavior across many accounts, instead of one account's
// history — not what Go type they carry, and sharing the type means
// JoinAnomalySignals renders both kinds for an audit event's metadata
// without a second near-identical helper.
const (
	// SignalAccountSpray fires when one IP's recent failures are spread
	// across more distinct targets than CredentialStuffingThresholds
	// allows.
	//
	// This is the gap per-account lockout structurally cannot cover:
	// lockout counts failures against ONE account, so an attacker
	// trying a single leaked password against ten thousand accounts
	// never trips it — every individual account sees exactly one
	// failure and looks like an ordinary typo. Only the IP's own
	// breadth gives the attack away.
	SignalAccountSpray AnomalySignal = "account_spray"

	// SignalUnknownAccountSpray qualifies SignalAccountSpray rather
	// than standing on its own: the spray is mostly against emails
	// that match no account here at all. It has no threshold of its
	// own and never fires alone, which is deliberate — a second
	// independent bar would either duplicate SignalAccountSpray (any
	// number high enough to matter also trips breadth) or leave a hole
	// for the mixed case (a few real accounts plus many unknown ones
	// clearing neither bar separately).
	//
	// Worth distinguishing because it says where the list came from. A
	// spray whose targets mostly exist means the attacker knows this
	// system's users; one whose targets mostly don't means a list
	// obtained elsewhere being tried blind, and the right response
	// (and the expected false-positive rate) differs.
	SignalUnknownAccountSpray AnomalySignal = "unknown_account_spray"
)

// CredentialStuffingObservations is how broadly one IP's recent failed
// attempts were spread, reduced to plain numbers. Same split as
// AnomalyObservations and for the same reason: whoever gathers this
// (the detector in package auth) owns the queries, Evaluate reads
// nothing itself, and the thresholds stay testable with no store at
// all.
type CredentialStuffingObservations struct {
	// DistinctAccounts is how many DIFFERENT existing accounts the IP
	// failed against — distinct accounts, not attempts, so an attacker
	// hammering one account cannot inflate it (that case is already
	// covered by lockout and by SignalUserFailureVelocity).
	DistinctAccounts int

	// UnknownTargetFailures counts failures against emails with no
	// account behind them. Attempts, not distinct addresses: the
	// attempted email is deliberately never stored (see
	// store.LoginAttempt — an engine that logged every probed address
	// would accumulate a list of email addresses, typos of real ones
	// included, that it has no other use for), so distinctness is not
	// knowable here. Counting attempts overcounts a single user
	// retrying one misspelled address, which is why the default
	// threshold below leaves room for it.
	UnknownTargetFailures int
}

// Breadth is the total target count the threshold is compared against.
// Known and unknown targets are added together on purpose: whether a
// sprayed email happened to exist in this system is a fact about the
// attacker's list, not about how broad the spray was.
func (o CredentialStuffingObservations) Breadth() int {
	return o.DistinctAccounts + o.UnknownTargetFailures
}

// CredentialStuffingThresholds tunes credential-stuffing detection.
// Separate from AnomalyThresholds, not another few fields on it, for
// two reasons: the two features are evaluated at different moments (an
// anomaly annotates a successful login, a spray is mostly visible in
// failures, so this one runs on both), and nesting would mean a host
// app tuning one silently zeroing the other — exactly the footgun the
// whole-struct default comparison in Config.applyDefaults exists to
// avoid.
type CredentialStuffingThresholds struct {
	// Window bounds how far back failures are counted. Longer than
	// AnomalyThresholds.Window's 15 minutes by default because breadth
	// accumulates more slowly than volume: a patient sprayer at one
	// attempt a minute never trips a 15-minute velocity threshold, yet
	// is unmistakable across an hour.
	//
	// Non-positive disables detection outright, the same as a zero
	// TargetAccounts below: there is no span of history to judge, and
	// counting over an empty range would report a clean result rather
	// than an unconfigured one.
	Window time.Duration

	// TargetAccounts is the Breadth() count within Window that flags
	// the IP. Zero disables credential-stuffing detection entirely,
	// matching how AnomalyThresholds treats its own zeroed knobs.
	TargetAccounts int

	// Cooldown suppresses repeat events for an IP already flagged this
	// recently. Without it a sustained spray emits one audit event per
	// failed attempt — thousands of identical events describing one
	// incident, which is worse for a monitoring pipeline than no
	// detection at all. Zero disables suppression and emits on every
	// crossing.
	Cooldown time.Duration
}

// DefaultCredentialStuffingThresholds is applied whenever
// Config.CredentialStuffingThresholds is left as the zero value. Like
// DefaultAnomalyThresholds these are not a security floor — detection
// is off entirely until Config.Anomalies is set, and these numbers only
// decide how chatty it is once it is on.
//
// TargetAccounts is set well above the "surely that's an attack" gut
// number because one office NAT, one mobile carrier gateway, or one
// corporate VPN egress legitimately produces many different users'
// failures from a single address, and UnknownTargetFailures counts
// attempts rather than distinct addresses. Cooldown is short enough
// that a sustained attack keeps showing up (roughly four events an
// hour) instead of going quiet after one alert.
var DefaultCredentialStuffingThresholds = CredentialStuffingThresholds{
	Window:         time.Hour,
	TargetAccounts: 10,
	Cooldown:       15 * time.Minute,
}

// Evaluate returns the signals this IP's breadth trips, or nil. Like
// AnomalyThresholds.Evaluate it reports and never decides: nothing here
// blocks a login, returns a sentinel error, or locks anything. A
// shared-egress false positive that blocked logins would take out every
// real user behind that address at once — a strictly worse outcome than
// the attack being merely recorded.
//
// Takes no attempt context, unlike its AnomalyThresholds counterpart:
// the IP being judged is the query key the observations were gathered
// under, and nothing about the individual attempt matters to a
// conclusion drawn from many.
func (t CredentialStuffingThresholds) Evaluate(obs CredentialStuffingObservations) []AnomalySignal {
	if t.TargetAccounts <= 0 || obs.Breadth() < t.TargetAccounts {
		return nil
	}

	signals := []AnomalySignal{SignalAccountSpray}
	// Strictly greater, so a spray split evenly between real and
	// unknown targets is not described as "mostly unknown."
	if obs.UnknownTargetFailures > obs.DistinctAccounts {
		signals = append(signals, SignalUnknownAccountSpray)
	}
	return signals
}
