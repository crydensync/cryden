package auth

import (
	"context"
	"strconv"
	"time"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
)

// stuffingAuditScanLimit bounds how many of the most recent
// store.EventCredentialStuffingDetected events are scanned to honour
// CredentialStuffingThresholds.Cooldown. Bounded because this runs on
// every failed login: it must stay one small indexed read.
//
// The limit degrades in the safe direction. Missing an older event
// means emitting a duplicate — over-reporting one incident, never
// missing one — and during an active attack the most recent events of
// this type are precisely the ones being looked for, which is exactly
// when the scan needs to be accurate.
const stuffingAuditScanLimit = 50

// detectCredentialStuffing judges one IP by the breadth of its recent
// failures and records store.EventCredentialStuffingDetected if that
// breadth looks like a spray across many accounts rather than someone
// forgetting their own password.
//
// It returns nothing, for the same reason detectLoginAnomalies does not:
// this reports, it never decides. No sentinel error, no block, no
// step-up. The failure mode of blocking here is severe and silent — one
// office NAT or carrier gateway wrongly judged takes out every real user
// behind that address at once, and the users affected have no way to
// tell why.
//
// Called AFTER the triggering attempt has been recorded, which is the
// opposite of detectLoginAnomalies' ordering and deliberate: an anomaly
// baseline must not contain the attempt it is judging, but a burst
// measurement must — the tenth distinct account a spray touches should
// trip a threshold of ten at ten, not at eleven.
func detectCredentialStuffing(
	ctx context.Context,
	anomalies store.AnomalyStore,
	audit store.AuditStore,
	log logger.Logger,
	thresholds security.CredentialStuffingThresholds,
	userID string,
	callerIP string,
) {
	// A non-positive Window or TargetAccounts is an off switch, not a
	// tuning value — see security.CredentialStuffingThresholds. An empty
	// callerIP is not evidence of anything either: without an IP there
	// is no subject to accumulate breadth against.
	if anomalies == nil || audit == nil || callerIP == "" {
		return
	}
	if thresholds.TargetAccounts <= 0 || thresholds.Window <= 0 {
		return
	}

	counts, err := anomalies.CountTargetsForIP(ctx, callerIP, time.Now().Add(-thresholds.Window))
	if err != nil {
		// Treated as "no evidence", like every other read in this
		// feature: a broken store must not be able to affect a login,
		// and inventing a verdict from a failed query would be worse
		// than staying quiet.
		log.Error("credential stuffing: per-IP target count failed", map[string]string{"error": err.Error(), "ip": callerIP})
		return
	}

	obs := security.CredentialStuffingObservations{
		DistinctAccounts:      counts.DistinctAccounts,
		UnknownTargetFailures: counts.UnknownTargetFailures,
	}
	signals := thresholds.Evaluate(obs)
	if len(signals) == 0 {
		return
	}

	if recentlyFlaggedForStuffing(ctx, audit, log, thresholds, callerIP) {
		log.Debug("credential stuffing: repeat within cooldown, not recorded", map[string]string{
			"ip":       callerIP,
			"cooldown": thresholds.Cooldown.String(),
		})
		return
	}

	metadata := map[string]string{
		"signals":           security.JoinAnomalySignals(signals),
		"distinct_accounts": strconv.Itoa(obs.DistinctAccounts),
		"unknown_targets":   strconv.Itoa(obs.UnknownTargetFailures),
		"window":            thresholds.Window.String(),
	}
	if err := audit.Record(ctx, store.AuditEvent{
		Type: store.EventCredentialStuffingDetected,
		// Incidental context — the account this particular attempt
		// named, empty when it named an unknown email. The IP is the
		// actual subject of the event.
		UserID:   userID,
		IP:       callerIP,
		Metadata: metadata,
	}); err != nil {
		log.Error("credential stuffing: audit record failed", map[string]string{"error": err.Error(), "ip": callerIP})
	}
	log.Warn("credential stuffing: IP flagged", map[string]string{
		"ip":                callerIP,
		"signals":           metadata["signals"],
		"distinct_accounts": metadata["distinct_accounts"],
		"unknown_targets":   metadata["unknown_targets"],
	})
}

// recentlyFlaggedForStuffing reports whether this IP already produced a
// credential-stuffing event inside thresholds.Cooldown, so a sustained
// spray describes itself in a handful of audit events instead of one per
// failed attempt. A monitoring pipeline drowned in thousands of
// identical events is no better served than one that got none.
//
// Fails open — a failed lookup emits rather than suppresses. The cost of
// being wrong that way is a duplicate event; the cost of the other
// direction is a missed attack.
func recentlyFlaggedForStuffing(
	ctx context.Context,
	audit store.AuditStore,
	log logger.Logger,
	thresholds security.CredentialStuffingThresholds,
	callerIP string,
) bool {
	if thresholds.Cooldown <= 0 {
		return false
	}

	events, err := audit.SearchByType(ctx, store.EventCredentialStuffingDetected, stuffingAuditScanLimit)
	if err != nil {
		log.Error("credential stuffing: cooldown lookup failed", map[string]string{"error": err.Error(), "ip": callerIP})
		return false
	}

	cutoff := time.Now().Add(-thresholds.Cooldown)
	for _, e := range events {
		if e.IP == callerIP && !e.CreatedAt.Before(cutoff) {
			return true
		}
	}
	return false
}
