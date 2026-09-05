package admin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// fakeAuditReader is the whole store a digest is allowed to see, and it
// records what was asked of it — several tests below are about which
// queries BuildDigest does *not* make.
type fakeAuditReader struct {
	counts    map[store.AuditEventType]int
	events    map[store.AuditEventType][]store.AuditEvent
	countErr  error
	searchErr error

	searched []store.AuditEventType // in call order
	limits   []int
}

func (f *fakeAuditReader) CountByType(ctx context.Context, since time.Time) (map[store.AuditEventType]int, error) {
	if f.countErr != nil {
		return nil, f.countErr
	}
	// Copied, like a real store's freshly scanned map: a caller mutating
	// the result must not reach back into the fixture.
	out := make(map[store.AuditEventType]int, len(f.counts))
	for eventType, n := range f.counts {
		out[eventType] = n
	}
	return out, nil
}

func (f *fakeAuditReader) SearchByType(ctx context.Context, eventType store.AuditEventType, limit int) ([]store.AuditEvent, error) {
	f.searched = append(f.searched, eventType)
	f.limits = append(f.limits, limit)
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	events := f.events[eventType]
	if len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

var _ AuditReader = (*fakeAuditReader)(nil)

func TestBuildDigest_CountsPassThrough(t *testing.T) {
	r := &fakeAuditReader{counts: map[store.AuditEventType]int{
		store.EventLoginSuccess: 41,
		store.EventLoginFailed:  9,
	}}
	since := time.Now().Add(-DefaultDigestWindow)

	d, err := BuildDigest(context.Background(), r, since)
	if err != nil {
		t.Fatalf("BuildDigest: %v", err)
	}
	if d.Counts[store.EventLoginSuccess] != 41 || d.Counts[store.EventLoginFailed] != 9 {
		t.Errorf("counts = %v, want login_success 41 and login_failed 9", d.Counts)
	}
	if d.Total() != 50 {
		t.Errorf("Total() = %d, want 50", d.Total())
	}
	if !d.Since.Equal(since) {
		t.Errorf("Since = %s, want %s", d.Since, since)
	}
	if d.Until.Before(d.Since) {
		t.Errorf("Until %s is before Since %s", d.Until, d.Since)
	}
}

// A quiet week must cost exactly one query: no attention type occurred,
// so there is nothing to fetch detail for.
func TestBuildDigest_QuietWindowMakesNoSearchCalls(t *testing.T) {
	r := &fakeAuditReader{counts: map[store.AuditEventType]int{}}

	d, err := BuildDigest(context.Background(), r, time.Now().Add(-DefaultDigestWindow))
	if err != nil {
		t.Fatalf("BuildDigest: %v", err)
	}
	if len(r.searched) != 0 {
		t.Errorf("SearchByType called for %v; an empty window needs no detail", r.searched)
	}
	if d.Total() != 0 {
		t.Errorf("Total() = %d, want 0", d.Total())
	}
}

// Detail is fetched only for attention types, and only for the ones
// that actually occurred. Routine volume is counted, never listed.
func TestBuildDigest_SearchesOnlyAttentionTypesThatOccurred(t *testing.T) {
	r := &fakeAuditReader{counts: map[store.AuditEventType]int{
		store.EventAccountLocked:      2,
		store.EventAnomalyDetected:    1,
		store.EventTokenReuseDetected: 0,   // present but zero
		store.EventLoginSuccess:       500, // routine, and not an attention type
	}}

	if _, err := BuildDigest(context.Background(), r, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("BuildDigest: %v", err)
	}

	want := map[store.AuditEventType]bool{store.EventAccountLocked: true, store.EventAnomalyDetected: true}
	if len(r.searched) != len(want) {
		t.Fatalf("searched %v, want exactly %v", r.searched, want)
	}
	for _, eventType := range r.searched {
		if !want[eventType] {
			t.Errorf("searched %s, which is either routine or had no events", eventType)
		}
	}
	for _, limit := range r.limits {
		if limit != digestHighlightLimit {
			t.Errorf("SearchByType limit = %d, want %d", limit, digestHighlightLimit)
		}
	}
}

// SearchByType has no window of its own, so it hands back events older
// than the digest covers. Those must not reach Highlights, or a digest
// would print last month's lockout as if it happened this week.
func TestBuildDigest_ExcludesHighlightsBeforeSince(t *testing.T) {
	now := time.Now()
	since := now.Add(-7 * 24 * time.Hour)
	r := &fakeAuditReader{
		counts: map[store.AuditEventType]int{store.EventAccountLocked: 2},
		events: map[store.AuditEventType][]store.AuditEvent{
			store.EventAccountLocked: {
				{Type: store.EventAccountLocked, UserID: "in-window", CreatedAt: now.Add(-time.Hour)},
				{Type: store.EventAccountLocked, UserID: "on-boundary", CreatedAt: since},
				{Type: store.EventAccountLocked, UserID: "too-old", CreatedAt: since.Add(-time.Nanosecond)},
			},
		},
	}

	d, err := BuildDigest(context.Background(), r, since)
	if err != nil {
		t.Fatalf("BuildDigest: %v", err)
	}
	if len(d.Highlights) != 2 {
		t.Fatalf("got %d highlights, want 2 (the boundary event counts, the one before it does not): %+v", len(d.Highlights), d.Highlights)
	}
	for _, e := range d.Highlights {
		if e.UserID == "too-old" {
			t.Error("an event from before the window reached Highlights")
		}
	}
}

func TestBuildDigest_HighlightsAreNewestFirstAcrossTypes(t *testing.T) {
	now := time.Now()
	r := &fakeAuditReader{
		counts: map[store.AuditEventType]int{store.EventAccountLocked: 1, store.EventAnomalyDetected: 2},
		events: map[store.AuditEventType][]store.AuditEvent{
			store.EventAccountLocked: {
				{Type: store.EventAccountLocked, UserID: "middle", CreatedAt: now.Add(-2 * time.Hour)},
			},
			store.EventAnomalyDetected: {
				{Type: store.EventAnomalyDetected, UserID: "newest", CreatedAt: now.Add(-time.Minute)},
				{Type: store.EventAnomalyDetected, UserID: "oldest", CreatedAt: now.Add(-5 * time.Hour)},
			},
		},
	}

	d, err := BuildDigest(context.Background(), r, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("BuildDigest: %v", err)
	}
	want := []string{"newest", "middle", "oldest"}
	if len(d.Highlights) != len(want) {
		t.Fatalf("got %d highlights, want %d", len(d.Highlights), len(want))
	}
	for i, userID := range want {
		if d.Highlights[i].UserID != userID {
			t.Errorf("highlight %d = %s, want %s (highlights are newest first, across types)", i, d.Highlights[i].UserID, userID)
		}
	}
}

// The cap bounds what a digest prints, not what it knows: the count
// stays exact even when only digestHighlightLimit events come back.
func TestBuildDigest_CountStaysExactWhenHighlightsAreCapped(t *testing.T) {
	now := time.Now()
	var events []store.AuditEvent
	for i := 0; i < 25; i++ {
		events = append(events, store.AuditEvent{Type: store.EventAccountLocked, CreatedAt: now.Add(-time.Duration(i) * time.Minute)})
	}
	r := &fakeAuditReader{
		counts: map[store.AuditEventType]int{store.EventAccountLocked: 25},
		events: map[store.AuditEventType][]store.AuditEvent{store.EventAccountLocked: events},
	}

	d, err := BuildDigest(context.Background(), r, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("BuildDigest: %v", err)
	}
	if len(d.Highlights) != digestHighlightLimit {
		t.Errorf("got %d highlights, want the cap of %d", len(d.Highlights), digestHighlightLimit)
	}
	if d.Counts[store.EventAccountLocked] != 25 {
		t.Errorf("count = %d, want the exact 25 despite the cap", d.Counts[store.EventAccountLocked])
	}
}

func TestBuildDigest_CountErrorIsReturned(t *testing.T) {
	sentinel := errors.New("connection refused")
	r := &fakeAuditReader{countErr: sentinel}

	_, err := BuildDigest(context.Background(), r, time.Now().Add(-time.Hour))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap %v", err, sentinel)
	}
	if !strings.Contains(err.Error(), "admin:") {
		t.Errorf("err = %q, want it to name the package", err)
	}
}

// A store that can count but fails on detail is an error, not a digest
// with the detail quietly missing: the four attention types are the
// reason someone opens this report.
func TestBuildDigest_SearchErrorIsReturned(t *testing.T) {
	sentinel := errors.New("statement timeout")
	r := &fakeAuditReader{
		counts:    map[store.AuditEventType]int{store.EventAccountLocked: 3},
		searchErr: sentinel,
	}

	_, err := BuildDigest(context.Background(), r, time.Now().Add(-time.Hour))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap %v", err, sentinel)
	}
	if !strings.Contains(err.Error(), string(store.EventAccountLocked)) {
		t.Errorf("err = %q, want it to name the type it was listing", err)
	}
}

// A fixed window, so the rendered header is exactly assertable rather
// than "something containing the word days".
func testDigest(counts map[store.AuditEventType]int, highlights ...store.AuditEvent) Digest {
	since := time.Date(2026, time.August, 30, 9, 0, 0, 0, time.UTC)
	return Digest{
		Since:      since,
		Until:      since.Add(DefaultDigestWindow),
		Counts:     counts,
		Highlights: highlights,
	}
}

func TestDigest_Text_Header(t *testing.T) {
	got := testDigest(map[store.AuditEventType]int{store.EventLoginSuccess: 1}).Text()

	wantHeader := "Security digest — 30 Aug 2026 09:00 UTC to 6 Sep 2026 09:00 UTC (7 days)"
	if !strings.HasPrefix(got, wantHeader) {
		t.Errorf("first line = %q, want it to start with %q", strings.SplitN(got, "\n", 2)[0], wantHeader)
	}
	if !strings.Contains(got, "1 event recorded in total.") {
		t.Errorf("missing singular total line:\n%s", got)
	}
}

// The window is printed in UTC whatever the machine's zone, because the
// same digest must read the same from a cron container or a laptop.
func TestDigest_Text_HeaderIsUTCRegardlessOfInputZone(t *testing.T) {
	tokyo := time.FixedZone("UTC+9", 9*60*60)
	d := Digest{
		Since:  time.Date(2026, time.August, 30, 18, 0, 0, 0, tokyo), // 09:00 UTC
		Until:  time.Date(2026, time.September, 6, 18, 0, 0, 0, tokyo),
		Counts: map[store.AuditEventType]int{store.EventLoginSuccess: 2},
	}

	if got := d.Text(); !strings.Contains(got, "30 Aug 2026 09:00 UTC to 6 Sep 2026 09:00 UTC") {
		t.Errorf("header did not convert to UTC:\n%s", got)
	}
}

func TestDigest_Text_QuietWindowSaysSoAndPrintsNoSections(t *testing.T) {
	got := testDigest(map[store.AuditEventType]int{}).Text()

	if !strings.Contains(got, "Nothing to report: no audit events were recorded in this window.") {
		t.Errorf("quiet window did not say so:\n%s", got)
	}
	for _, section := range digestSections {
		if strings.Contains(got, section.title) {
			t.Errorf("section %q printed for an empty window:\n%s", section.title, got)
		}
	}
}

func TestDigest_Text_OmitsSectionsWithNothingInThem(t *testing.T) {
	got := testDigest(map[store.AuditEventType]int{store.EventAPIKeyCreated: 2}).Text()

	if !strings.Contains(got, "API keys") {
		t.Errorf("the one section with events is missing:\n%s", got)
	}
	if strings.Contains(got, "Needs attention") || strings.Contains(got, "Sign-ins") {
		t.Errorf("printed a section with no events in it:\n%s", got)
	}
	// Nor a zero line for the other types inside the section that did print.
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "0 ") {
			t.Errorf("printed a zero count line %q:\n%s", line, got)
		}
	}
}

// What needs a human comes first; routine volume comes last.
func TestDigest_Text_SectionOrder(t *testing.T) {
	got := testDigest(map[store.AuditEventType]int{
		store.EventAPIKeyCreated: 1,
		store.EventLoginSuccess:  2,
		store.EventAccountLocked: 3,
		store.EventSignupSuccess: 4,
		store.EventOAuthLinked:   5,
		"acme_invoice_paid":      6,
	}).Text()

	want := []string{"Needs attention", "Accounts", "Sign-ins", "Sign-in methods", "API keys", "Other events"}
	at := -1
	for _, title := range want {
		i := strings.Index(got, title)
		if i < 0 {
			t.Fatalf("section %q missing:\n%s", title, got)
		}
		if i < at {
			t.Errorf("section %q is out of order:\n%s", title, got)
		}
		at = i
	}
}

func TestDigest_Text_Pluralization(t *testing.T) {
	one := testDigest(map[store.AuditEventType]int{store.EventAccountLocked: 1}).Text()
	if !strings.Contains(one, "1 account was locked") {
		t.Errorf("singular phrase missing:\n%s", one)
	}

	many := testDigest(map[store.AuditEventType]int{store.EventAccountLocked: 4}).Text()
	if !strings.Contains(many, "4 accounts were locked") {
		t.Errorf("plural phrase missing:\n%s", many)
	}
}

// A host's own event types, and any the engine gains after the section
// table was written, are reported rather than dropped.
func TestDigest_Text_UnknownTypesUnderOtherEvents(t *testing.T) {
	got := testDigest(map[store.AuditEventType]int{
		"acme_subscription_cancelled": 2,
		"acme_invoice_paid":           7,
		store.EventLoginSuccess:       1,
	}).Text()

	other := got[strings.Index(got, "Other events"):]
	if !strings.Contains(other, "7 acme_invoice_paid") || !strings.Contains(other, "2 acme_subscription_cancelled") {
		t.Errorf("unknown types not reported:\n%s", got)
	}
	// Sorted by name, so the same digest never renders two ways.
	if strings.Index(other, "acme_invoice_paid") > strings.Index(other, "acme_subscription_cancelled") {
		t.Errorf("unknown types are not sorted:\n%s", other)
	}
	if strings.Contains(other, "login_success") {
		t.Errorf("a type the engine defines was reported as unknown:\n%s", other)
	}
}

func TestDigest_Text_HighlightDetail(t *testing.T) {
	at := time.Date(2026, time.September, 2, 14, 31, 0, 0, time.UTC)
	got := testDigest(
		map[store.AuditEventType]int{store.EventAnomalyDetected: 1},
		store.AuditEvent{
			Type:      store.EventAnomalyDetected,
			UserID:    "9f1c2a44-0000-4000-8000-000000000001",
			IP:        "203.0.113.9",
			CreatedAt: at,
			Metadata:  map[string]string{"signals": "new_ip,new_device", "email": "raymondproguy@dev.com"},
		},
	).Text()

	want := "2 Sep 14:31 UTC — user 9f1c2a44-0000-4000-8000-000000000001, IP 203.0.113.9 (email=raymondproguy@dev.com, signals=new_ip,new_device)"
	if !strings.Contains(got, want) {
		t.Errorf("detail line missing.\nwant: %s\ngot:\n%s", want, got)
	}
	// Indented under its count line, not flush with the section heading.
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "2 Sep 14:31") && !strings.HasPrefix(line, "    ") {
			t.Errorf("detail line is not indented: %q", line)
		}
	}
}

// Credential stuffing against an address with no account: there is no
// user to name, and the line has to say that rather than print "user ".
func TestDigest_Text_HighlightWithNoUser(t *testing.T) {
	got := testDigest(
		map[store.AuditEventType]int{store.EventCredentialStuffingDetected: 1},
		store.AuditEvent{
			Type:      store.EventCredentialStuffingDetected,
			IP:        "198.51.100.7",
			CreatedAt: time.Date(2026, time.September, 3, 4, 5, 0, 0, time.UTC),
		},
	).Text()

	if !strings.Contains(got, "no account attached, IP 198.51.100.7") {
		t.Errorf("event with no user rendered wrong:\n%s", got)
	}
	if strings.Contains(got, "user ,") {
		t.Errorf("printed an empty user ID:\n%s", got)
	}
}

func TestDigest_Text_CapNoteCountsAgainstTheRealTotal(t *testing.T) {
	at := time.Date(2026, time.September, 4, 8, 0, 0, 0, time.UTC)
	var highlights []store.AuditEvent
	for i := 0; i < digestHighlightLimit; i++ {
		highlights = append(highlights, store.AuditEvent{
			Type:      store.EventTokenReuseDetected,
			UserID:    "user-1",
			CreatedAt: at.Add(-time.Duration(i) * time.Minute),
		})
	}
	got := testDigest(map[store.AuditEventType]int{store.EventTokenReuseDetected: 1200}, highlights...).Text()

	if !strings.Contains(got, "1,200 refresh tokens") {
		t.Errorf("count line missing or unseparated:\n%s", got)
	}
	if want := "(the 10 most recent of 1,200 shown)"; !strings.Contains(got, want) {
		t.Errorf("cap note missing %q:\n%s", want, got)
	}
}

// Nothing is said about truncation when nothing was truncated.
func TestDigest_Text_NoCapNoteWhenEverythingIsShown(t *testing.T) {
	got := testDigest(
		map[store.AuditEventType]int{store.EventAccountLocked: 2},
		store.AuditEvent{Type: store.EventAccountLocked, UserID: "a", CreatedAt: time.Now()},
		store.AuditEvent{Type: store.EventAccountLocked, UserID: "b", CreatedAt: time.Now()},
	).Text()

	if strings.Contains(got, "most recent of") {
		t.Errorf("cap note printed when all events were shown:\n%s", got)
	}
}

// Map iteration must not reach the output: two renders of one Digest are
// the same bytes, or a digest mailed weekly looks like it changed when
// it did not.
func TestDigest_Text_IsDeterministic(t *testing.T) {
	d := testDigest(map[store.AuditEventType]int{
		store.EventLoginSuccess: 3, store.EventLoginFailed: 2, store.EventSignupSuccess: 1,
		store.EventOAuthLinked: 1, store.EventAPIKeyCreated: 1,
		"zeta_host_event": 1, "alpha_host_event": 1,
	})
	first := d.Text()
	for i := 0; i < 20; i++ {
		if got := d.Text(); got != first {
			t.Fatalf("render %d differs:\n%s\n---\n%s", i, first, got)
		}
	}
}

func TestFormatCount(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want string
	}{{0, "0"}, {7, "7"}, {999, "999"}, {1000, "1,000"}, {12481, "12,481"}, {1000000, "1,000,000"}, {-1234, "-1,234"}} {
		if got := formatCount(tc.n); got != tc.want {
			t.Errorf("formatCount(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

func TestHumanWindow(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{DefaultDigestWindow, "7 days"},
		{DefaultDigestWindow + 3*time.Second, "7 days"}, // the real one: Until is read after the queries
		{24 * time.Hour, "1 day"},
		{36 * time.Hour, "2 days"},
		{2 * time.Hour, "2 hours"},
		{time.Hour, "1 hour"},
		{90 * time.Second, "2 minutes"},
		{time.Minute, "1 minute"},
		{30 * time.Second, "under a minute"},
		{-time.Hour, "1 hour"}, // Until before Since is nonsense, not a crash
	} {
		if got := humanWindow(tc.d); got != tc.want {
			t.Errorf("humanWindow(%s) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

// The section table is the digest's vocabulary. A type listed twice
// would be counted once and printed twice; an empty phrase would render
// a bare number.
func TestDigestSections_AreWellFormed(t *testing.T) {
	seen := make(map[store.AuditEventType]string)
	for _, section := range digestSections {
		if section.title == "" || len(section.phrases) == 0 {
			t.Errorf("section %q is empty", section.title)
		}
		for _, p := range section.phrases {
			if where, dup := seen[p.eventType]; dup {
				t.Errorf("%s is in both %q and %q", p.eventType, where, section.title)
			}
			seen[p.eventType] = section.title
			if p.eventType == "" || p.singular == "" || p.plural == "" {
				t.Errorf("incomplete phrase for %q in %q", p.eventType, section.title)
			}
			if p.singular == p.plural {
				t.Errorf("%s has the same phrase in both numbers: %q", p.eventType, p.singular)
			}
		}
	}
}

// digestAttentionTypes drives which types get detail fetched; it is
// derived from the first section so the queries and the printed output
// cannot drift apart.
func TestDigestAttentionTypes_MatchFirstSection(t *testing.T) {
	got := digestAttentionTypes()
	if len(got) != len(digestSections[0].phrases) {
		t.Fatalf("got %d attention types, want %d", len(got), len(digestSections[0].phrases))
	}
	for i, p := range digestSections[0].phrases {
		if got[i] != p.eventType {
			t.Errorf("attention type %d = %s, want %s", i, got[i], p.eventType)
		}
	}
}

func TestCapNote(t *testing.T) {
	for _, tc := range []struct {
		shown, total int
		want         string
	}{
		{0, 0, ""},
		{0, 5, ""}, // nothing fetched: no claim about what was shown
		{3, 3, ""}, // everything shown
		{3, 2, ""}, // more detail than the count: say nothing rather than something absurd
		{1, 4, "(the most recent of 4 shown)"},
		{10, 1200, "(the 10 most recent of 1,200 shown)"},
	} {
		if got := capNote(tc.shown, tc.total); got != tc.want {
			t.Errorf("capNote(%d, %d) = %q, want %q", tc.shown, tc.total, got, tc.want)
		}
	}
}
