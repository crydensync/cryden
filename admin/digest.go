// Package admin holds the read-only reporting surface behind cryden's
// admin features: information for a human to read and act on, and
// nothing else.
//
// Nothing here writes anything, and that is enforced rather than
// promised. Every read goes through a narrow interface carrying only
// the store methods a report needs — see AuditReader, which has no
// Record — so a report cannot lock an account, rewrite a config value
// or append an audit event, because it is never handed anything that
// could. Any future addition to this package is held to the same rule.
//
// Distinct from package ai, which exists for the one feature that does
// involve a language model: nothing in this package calls out to
// anything, and a digest is composed by the code below rather than
// generated.
package admin

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// DefaultDigestWindow is how far back a weekly digest looks.
const DefaultDigestWindow = 7 * 24 * time.Hour

// digestHighlightLimit caps how many individual events of one
// attention-worthy type a digest spells out in full. The counts beside
// them are always exact and come from the database, so this bounds how
// much a digest prints, never what it knows: past the cap the text says
// how many it is showing out of how many there were.
const digestHighlightLimit = 10

// AuditReader is the read-only slice of store.AuditStore a digest
// needs. store.AuditStore satisfies it as it stands; the point of
// naming it separately is that Record is not in it.
type AuditReader interface {
	CountByType(ctx context.Context, since time.Time) (map[store.AuditEventType]int, error)
	SearchByType(ctx context.Context, eventType store.AuditEventType, limit int) ([]store.AuditEvent, error)
}

// Digest is one window of audit history, summarised.
//
// Counts is exact for every type, straight from the database, and
// includes types this engine does not define — a host recording its own
// events into the same table sees them rather than losing them.
// Highlights is illustrative: the individual attention-worthy events,
// newest first, capped at digestHighlightLimit per type.
type Digest struct {
	Since      time.Time
	Until      time.Time
	Counts     map[store.AuditEventType]int
	Highlights []store.AuditEvent
}

// BuildDigest reads the audit history recorded at or after since and
// summarises it. The window always ends now: SearchByType returns the
// newest events of a type and nothing else, so an explicit end bound
// would be a window whose detail rows cannot be reached without another
// store method — better to have no end bound than one whose highlights
// silently come back empty.
//
// One CountByType query, plus one SearchByType per attention-worthy
// type that actually occurred: a quiet week costs exactly one query.
func BuildDigest(ctx context.Context, r AuditReader, since time.Time) (Digest, error) {
	counts, err := r.CountByType(ctx, since)
	if err != nil {
		return Digest{}, fmt.Errorf("admin: counting audit events: %w", err)
	}

	d := Digest{Since: since.UTC(), Counts: counts}
	for _, eventType := range digestAttentionTypes() {
		if counts[eventType] == 0 {
			continue
		}
		events, err := r.SearchByType(ctx, eventType, digestHighlightLimit)
		if err != nil {
			return Digest{}, fmt.Errorf("admin: listing %s events: %w", eventType, err)
		}
		for _, e := range events {
			// SearchByType has no window, so its results reach back past
			// since. Skipped rather than broken out of: the newest-first
			// contract makes a break equivalent, but nothing about the
			// counts above depends on that contract and neither should
			// this.
			if e.CreatedAt.Before(since) {
				continue
			}
			d.Highlights = append(d.Highlights, e)
		}
	}
	sort.SliceStable(d.Highlights, func(i, j int) bool {
		return d.Highlights[i].CreatedAt.After(d.Highlights[j].CreatedAt)
	})

	// Read after the queries, so everything counted really did happen at
	// or before the window this digest claims to cover.
	d.Until = time.Now().UTC()
	return d, nil
}

// Total is how many events the window holds, across every type.
func (d Digest) Total() int {
	total := 0
	for _, n := range d.Counts {
		total += n
	}
	return total
}

// digestPhrase is one event type and how to say it in a sentence, in
// both numbers. The wording is a predicate: a rendered line is the
// count followed by the phrase, so "3" + "accounts were locked …".
type digestPhrase struct {
	eventType store.AuditEventType
	singular  string
	plural    string
}

// digestSection groups event types under a heading. Order is the order
// they print in, deliberately: what needs a human comes first, and
// routine volume comes last.
type digestSection struct {
	title   string
	phrases []digestPhrase
}

// digestSections covers all 31 event types the engine records, each in
// exactly one section. Anything not here — a host's own event type, or
// one added to the engine after this table was written — is counted and
// printed under "Other events" instead of being dropped, which is why
// this table being out of date degrades a digest rather than hiding
// something from it.
var digestSections = []digestSection{
	{
		// The same four events item 17 grouped as "something is wrong",
		// and for the same reason: all four are rare by construction, and
		// all four are why somebody reads a digest at all. These are the
		// types whose individual events get spelled out below their count.
		title: "Needs attention",
		phrases: []digestPhrase{
			{store.EventAccountLocked, "account was locked after repeated failed sign-ins", "accounts were locked after repeated failed sign-ins"},
			{store.EventTokenReuseDetected, "refresh token was reused after rotation, revoking its whole session family", "refresh tokens were reused after rotation, revoking their whole session families"},
			{store.EventAnomalyDetected, "sign-in was flagged as anomalous", "sign-ins were flagged as anomalous"},
			{store.EventCredentialStuffingDetected, "credential-stuffing burst was detected", "credential-stuffing bursts were detected"},
		},
	},
	{
		title: "Accounts",
		phrases: []digestPhrase{
			{store.EventSignupSuccess, "account was created", "accounts were created"},
			{store.EventAccountDeleted, "account was deleted", "accounts were deleted"},
			{store.EventPasswordChanged, "password was changed", "passwords were changed"},
			{store.EventPasswordBreachRejected, "password was refused for appearing in a breach corpus", "passwords were refused for appearing in a breach corpus"},
			{store.EventPasswordHashUpgraded, "password hash was upgraded on sign-in", "password hashes were upgraded on sign-in"},
			{store.EventEmailChangeRequested, "email change was requested", "email changes were requested"},
			{store.EventEmailChanged, "email address was changed", "email addresses were changed"},
		},
	},
	{
		title: "Sign-ins",
		phrases: []digestPhrase{
			{store.EventLoginSuccess, "sign-in succeeded", "sign-ins succeeded"},
			{store.EventLoginFailed, "sign-in attempt failed", "sign-in attempts failed"},
			{store.EventMagicLinkRequested, "magic link was requested", "magic links were requested"},
			{store.EventLogout, "session was signed out", "sessions were signed out"},
			{store.EventLogoutAll, "account signed out of every session at once", "accounts signed out of every session at once"},
			{store.EventSessionRevoked, "session was revoked", "sessions were revoked"},
			{store.EventTokenRotated, "access token was refreshed", "access tokens were refreshed"},
		},
	},
	{
		title: "Sign-in methods",
		phrases: []digestPhrase{
			{store.EventOAuthLinked, "OAuth identity was linked", "OAuth identities were linked"},
			{store.EventTOTPEnabled, "authenticator app was enrolled", "authenticator apps were enrolled"},
			{store.EventTOTPDisabled, "authenticator app was turned off", "authenticator apps were turned off"},
			{store.EventTOTPChallengeFailed, "authenticator code was rejected", "authenticator codes were rejected"},
			{store.EventWebAuthnRegistered, "passkey was registered", "passkeys were registered"},
			{store.EventWebAuthnRemoved, "passkey was removed", "passkeys were removed"},
			{store.EventWebAuthnChallengeFailed, "passkey challenge failed", "passkey challenges failed"},
			{store.EventRecoveryCodesGenerated, "set of recovery codes was generated", "sets of recovery codes were generated"},
			{store.EventRecoveryCodeUsed, "recovery code was used to sign in", "recovery codes were used to sign in"},
			{store.EventRecoveryCodeFailed, "recovery code was rejected", "recovery codes were rejected"},
		},
	},
	{
		title: "API keys",
		phrases: []digestPhrase{
			{store.EventAPIKeyCreated, "API key was created", "API keys were created"},
			{store.EventAPIKeyRevoked, "API key was revoked", "API keys were revoked"},
			{store.EventAPIKeyRejected, "API key was presented after being revoked or expiring", "API keys were presented after being revoked or expiring"},
		},
	},
}

// digestAttentionTypes is the first section's types — the ones whose
// individual events are worth printing. Derived from digestSections
// rather than listed twice, so the section that shows detail and the
// queries that fetch it cannot drift apart.
func digestAttentionTypes() []store.AuditEventType {
	types := make([]store.AuditEventType, 0, len(digestSections[0].phrases))
	for _, p := range digestSections[0].phrases {
		types = append(types, p.eventType)
	}
	return types
}

// Text renders the digest as the report a human reads: the window, the
// total, then one section per group of event types, each line a count
// and a sentence. Types with no events in the window are left out
// entirely, and so are sections with nothing in them — a digest of a
// quiet week should be short, not a wall of zeroes.
//
// Deterministic: the same Digest always renders the same text, in this
// order, with no clock read and no map iteration reaching the output.
func (d Digest) Text() string {
	var b strings.Builder

	fmt.Fprintf(&b, "Security digest — %s to %s (%s)\n",
		formatDigestTime(d.Since), formatDigestTime(d.Until), humanWindow(d.Until.Sub(d.Since)))

	total := d.Total()
	if total == 0 {
		b.WriteString("\nNothing to report: no audit events were recorded in this window.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "%s recorded in total.\n", pluralize(total, "event", "events"))

	highlights := d.highlightsByType()
	for _, section := range digestSections {
		var lines []string
		for _, p := range section.phrases {
			n := d.Counts[p.eventType]
			if n == 0 {
				continue
			}
			lines = append(lines, "  "+formatCount(n)+" "+phraseFor(p, n))
			for _, e := range highlights[p.eventType] {
				lines = append(lines, "    "+describeEvent(e))
			}
			// Only ever says this when detail was cut, and says it against
			// the exact count rather than the cap: the number beside the
			// heading is never the one that was truncated.
			if shown := len(highlights[p.eventType]); shown > 0 && shown < n {
				lines = append(lines, fmt.Sprintf("    (the %d most recent of %s shown)", shown, formatCount(n)))
			}
		}
		if len(lines) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n%s\n%s\n", section.title, strings.Join(lines, "\n"))
	}

	if others := d.unclassifiedTypes(); len(others) > 0 {
		b.WriteString("\nOther events (types this engine does not define)\n")
		for _, eventType := range others {
			fmt.Fprintf(&b, "  %s %s\n", formatCount(d.Counts[eventType]), eventType)
		}
	}

	return b.String()
}

// highlightsByType regroups Highlights for rendering, preserving the
// newest-first order they were sorted into.
func (d Digest) highlightsByType() map[store.AuditEventType][]store.AuditEvent {
	byType := make(map[store.AuditEventType][]store.AuditEvent)
	for _, e := range d.Highlights {
		byType[e.Type] = append(byType[e.Type], e)
	}
	return byType
}

// unclassifiedTypes are the counted types no section claims, sorted by
// name so the output does not depend on map order. These are the reason
// a digest cannot silently lose an event type: an unrecognised type is
// reported as itself rather than skipped.
func (d Digest) unclassifiedTypes() []store.AuditEventType {
	classified := make(map[store.AuditEventType]struct{})
	for _, section := range digestSections {
		for _, p := range section.phrases {
			classified[p.eventType] = struct{}{}
		}
	}

	var others []store.AuditEventType
	for eventType, n := range d.Counts {
		if n == 0 {
			continue
		}
		if _, known := classified[eventType]; !known {
			others = append(others, eventType)
		}
	}
	sort.Slice(others, func(i, j int) bool { return others[i] < others[j] })
	return others
}

// describeEvent is one highlight line: when, to whom, from where, and
// whatever metadata the event carried. The user ID is printed in full
// because a truncated one cannot be looked up, which is the only reason
// an admin is reading this line.
func describeEvent(e store.AuditEvent) string {
	who := "no account attached"
	if e.UserID != "" {
		who = "user " + e.UserID
	}
	parts := []string{who}
	if e.IP != "" {
		parts = append(parts, "IP "+e.IP)
	}

	line := formatDetailTime(e.CreatedAt) + " — " + strings.Join(parts, ", ")
	if meta := formatMetadata(e.Metadata); meta != "" {
		line += " (" + meta + ")"
	}
	return line
}

// formatMetadata renders every key an event carried, sorted. Nothing is
// filtered or renamed: the metadata keys are the detail behind the
// event — which anomaly signals fired, why a key was refused — and a
// digest that dropped the ones it did not recognise would hide exactly
// the events worth reading about.
func formatMetadata(metadata map[string]string) string {
	if len(metadata) == 0 {
		return ""
	}
	keys := make([]string, 0, len(metadata))
	for k := range metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+metadata[k])
	}
	return strings.Join(pairs, ", ")
}

// formatDigestTime stamps the window's two ends. Everything a digest
// prints is converted to UTC first: the same digest must read the same
// whether it was rendered on the app server, in a cron container, or on
// a laptop, and audit rows are stored in UTC to begin with.
func formatDigestTime(t time.Time) string {
	return t.UTC().Format("2 Jan 2006 15:04 MST")
}

// formatDetailTime drops the year from a highlight line — every one of
// them is inside the window whose full dates are in the header.
func formatDetailTime(t time.Time) string {
	return t.UTC().Format("2 Jan 15:04 MST")
}

// humanWindow says how long the window was in the largest unit that
// still reads naturally, rounded to the nearest one. It exists so the
// header can say "7 days" rather than "168h0m0.002s": the window ends
// when the digest is built, so a raw Duration is never round.
func humanWindow(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d >= 24*time.Hour:
		return pluralize(int((d+12*time.Hour)/(24*time.Hour)), "day", "days")
	case d >= time.Hour:
		return pluralize(int((d+30*time.Minute)/time.Hour), "hour", "hours")
	case d >= time.Minute:
		return pluralize(int((d+30*time.Second)/time.Minute), "minute", "minutes")
	default:
		return "under a minute"
	}
}

// pluralize is the count and its noun: "1 day", "7 days".
func pluralize(n int, singular, plural string) string {
	if n == 1 {
		return formatCount(n) + " " + singular
	}
	return formatCount(n) + " " + plural
}

// phraseFor picks the phrase matching the count. The phrases are whole
// predicates rather than nouns with an -s bolted on, because "2 accounts
// were locked" and "1 account was locked" differ in the verb too.
func phraseFor(p digestPhrase, n int) string {
	if n == 1 {
		return p.singular
	}
	return p.plural
}

// formatCount groups thousands, so a bad week reads as "12,481 sign-ins
// failed" rather than "12481". Hand-rolled: a full localisation library
// is not worth a dependency for one separator, and this report is
// English-only anyway — the same reason the phrases above are literals.
func formatCount(n int) string {
	s := strconv.Itoa(n)
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign, s = "-", s[1:]
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return sign + s
}
