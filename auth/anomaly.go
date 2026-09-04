package auth

import (
	"context"
	"strconv"
	"time"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
)

// tokenReuseAuditScanLimit bounds how many of a user's most recent
// audit events are scanned for token-reuse history. Bounded on purpose:
// this runs on every successful login, so it must stay a single small
// indexed read. AuditStore has no by-user-AND-type query (ListByUser is
// per-user, SearchByType is system-wide), so the filtering happens here
// — which means a user with more than this many events since their last
// reuse event will not trip the signal. That's an acceptable miss for a
// report-only annotation, and the reuse event itself is still in the
// audit trail regardless.
const tokenReuseAuditScanLimit = 100

// detectLoginAnomalies evaluates one primary-authentication success
// against the account's recent history and records
// store.EventAnomalyDetected if anything looks unusual.
//
// It returns nothing. That is deliberate and not an oversight: this
// feature reports, it never decides. There is no error for a caller to
// branch on, no sentinel for "suspicious," and no way for a failing
// AnomalyStore to stop a legitimate login — every storage error below
// is logged and treated as "no evidence." A detector that can lock
// people out of their own accounts on a false positive (travel, a new
// browser, a shared office IP) is worse than no detector.
//
// Ordering matters: observations are gathered BEFORE this attempt is
// recorded, so the attempt can't appear in its own baseline and quietly
// mark its own IP familiar.
func detectLoginAnomalies(
	ctx context.Context,
	anomalies store.AnomalyStore,
	sessions store.SessionStore,
	audit store.AuditStore,
	log logger.Logger,
	thresholds security.AnomalyThresholds,
	user store.User,
	callerIP string,
	userAgent string,
) {
	if anomalies == nil {
		return
	}

	attempt := security.LoginAttemptContext{IP: callerIP, UserAgent: userAgent}
	obs := gatherObservations(ctx, anomalies, sessions, audit, log, thresholds, user.ID, callerIP)
	signals := thresholds.Evaluate(attempt, obs)

	if len(signals) > 0 {
		metadata := map[string]string{"signals": security.JoinAnomalySignals(signals)}
		// Only the counts behind signals that actually fired — a
		// metadata blob of mostly-zero fields makes the ones that matter
		// harder to spot in whatever the host app pipes this into.
		for _, s := range signals {
			switch s {
			case security.SignalUserFailureVelocity:
				metadata["user_failures"] = strconv.Itoa(obs.RecentUserFailures)
			case security.SignalIPFailureVelocity:
				metadata["ip_failures"] = strconv.Itoa(obs.RecentIPFailures)
			case security.SignalTokenReuse:
				metadata["token_reuse_events"] = strconv.Itoa(obs.RecentTokenReuseEvents)
			case security.SignalConcurrentSessions:
				metadata["active_sessions"] = strconv.Itoa(obs.ActiveSessions)
			}
		}
		if err := audit.Record(ctx, store.AuditEvent{
			Type:     store.EventAnomalyDetected,
			UserID:   user.ID,
			IP:       callerIP,
			Metadata: metadata,
		}); err != nil {
			log.Error("anomaly: audit record failed", map[string]string{"error": err.Error(), "user_id": user.ID})
		}
		log.Warn("anomaly: login flagged", map[string]string{
			"user_id": user.ID,
			"ip":      callerIP,
			"signals": metadata["signals"],
		})
	}

	RecordLoginAttempt(ctx, anomalies, log, store.LoginAttempt{
		UserID:    user.ID,
		IP:        callerIP,
		UserAgent: userAgent,
		Outcome:   store.OutcomeSuccess,
	})
}

// gatherObservations turns four storage reads into the plain snapshot
// security.AnomalyThresholds.Evaluate judges. Each read degrades
// independently: a failure leaves that one field zero-valued rather
// than abandoning the whole pass, so a broken AnomalyStore doesn't also
// blind the session-count and token-reuse signals.
func gatherObservations(
	ctx context.Context,
	anomalies store.AnomalyStore,
	sessions store.SessionStore,
	audit store.AuditStore,
	log logger.Logger,
	thresholds security.AnomalyThresholds,
	userID string,
	callerIP string,
) security.AnomalyObservations {
	var obs security.AnomalyObservations
	now := time.Now()

	recent, err := anomalies.ListRecentSuccesses(ctx, userID, thresholds.HistorySize)
	if err != nil {
		log.Error("anomaly: recent-success lookup failed", map[string]string{"error": err.Error(), "user_id": userID})
	} else {
		// HasLoginHistory stays false when there's nothing here, which
		// suppresses new_ip/new_device for a first-ever login — there is
		// no baseline yet to deviate from. It also, deliberately, keeps
		// the signals quiet when the read failed above: inventing
		// "everything is unfamiliar" out of a storage error would flag
		// every login during an outage.
		obs.HasLoginHistory = len(recent) > 0
		for _, a := range recent {
			if a.IP != "" {
				obs.KnownIPs = append(obs.KnownIPs, a.IP)
			}
			if a.UserAgent != "" {
				obs.KnownUserAgents = append(obs.KnownUserAgents, a.UserAgent)
			}
		}
	}

	since := now.Add(-thresholds.Window)
	if count, err := anomalies.CountFailuresForUser(ctx, userID, since); err != nil {
		log.Error("anomaly: per-user failure count failed", map[string]string{"error": err.Error(), "user_id": userID})
	} else {
		obs.RecentUserFailures = count
	}

	if count, err := anomalies.CountFailuresForIP(ctx, callerIP, since); err != nil {
		log.Error("anomaly: per-IP failure count failed", map[string]string{"error": err.Error(), "ip": callerIP})
	} else {
		obs.RecentIPFailures = count
	}

	if sessions != nil {
		if active, err := sessions.ListByUser(ctx, userID); err != nil {
			log.Error("anomaly: active-session count failed", map[string]string{"error": err.Error(), "user_id": userID})
		} else {
			// ListByUser already filters out revoked sessions in every
			// implementation, so this is the active count, not a total.
			obs.ActiveSessions = len(active)
		}
	}

	if audit != nil && thresholds.TokenReuseLookback > 0 {
		events, err := audit.ListByUser(ctx, userID, tokenReuseAuditScanLimit)
		if err != nil {
			log.Error("anomaly: token-reuse lookup failed", map[string]string{"error": err.Error(), "user_id": userID})
		} else {
			cutoff := now.Add(-thresholds.TokenReuseLookback)
			for _, e := range events {
				if e.Type == store.EventTokenReuseDetected && !e.CreatedAt.Before(cutoff) {
					obs.RecentTokenReuseEvents++
				}
			}
		}
	}

	return obs
}

// RecordLoginAttempt stores one observation, best-effort. Exported so
// every primary-auth path can feed the same history — including the
// failure paths, which are what per-user and per-IP velocity are
// counted from. A nil store is a no-op, so callers never need to check.
func RecordLoginAttempt(ctx context.Context, anomalies store.AnomalyStore, log logger.Logger, attempt store.LoginAttempt) {
	if anomalies == nil {
		return
	}
	if err := anomalies.RecordAttempt(ctx, attempt); err != nil {
		log.Error("anomaly: attempt record failed", map[string]string{"error": err.Error()})
	}
}
