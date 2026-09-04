package session

import (
	"context"
	"errors"
	"testing"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
)

const (
	chromeWindows = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	safariIPhone  = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
)

// stubGeolocator stands in for the implementation a host app supplies.
// It counts calls because "ask once per distinct IP" is a real promise
// this package makes to whoever pays for those lookups.
type stubGeolocator struct {
	byIP  map[string]security.Location
	err   error
	calls int
	seen  []string
}

func (g *stubGeolocator) Locate(_ context.Context, ip string) (security.Location, error) {
	g.calls++
	g.seen = append(g.seen, ip)
	if g.err != nil {
		return security.Location{}, g.err
	}
	return g.byIP[ip], nil
}

var _ security.IPGeolocator = (*stubGeolocator)(nil)

func TestListNamed_LabelsDeviceAndLocation(t *testing.T) {
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	sessions.Create(ctx, store.Session{
		ID: "s1", FamilyID: "s1", UserID: "user-1",
		IP: "1.2.3.4", UserAgent: chromeWindows, TokenHash: "hash-1",
	})
	geo := &stubGeolocator{byIP: map[string]security.Location{
		"1.2.3.4": {City: "San Francisco", Region: "CA"},
	}}

	list, err := ListNamed(ctx, sessions, geo, noopLogger{}, "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 named session, got %d", len(list))
	}

	got := list[0]
	if got.Label != "Chrome on Windows — San Francisco, CA" {
		t.Errorf("unexpected label: %q", got.Label)
	}
	// The parsed parts travel alongside the label so a UI can group or
	// sort by them without parsing the string back apart.
	if got.Device.Browser != "Chrome" || got.Device.OS != "Windows" || got.Device.Form != security.FormDesktop {
		t.Errorf("unexpected device: %+v", got.Device)
	}
	if got.Location.City != "San Francisco" {
		t.Errorf("unexpected location: %+v", got.Location)
	}
	// The embedded PublicSession is what makes this usable as an
	// HTTP-facing DTO on its own: the raw values stay available, the
	// secret ones were never there.
	if got.ID != "s1" || got.IP != "1.2.3.4" || got.UserAgent != chromeWindows {
		t.Errorf("expected the public session fields to be carried through, got %+v", got.PublicSession)
	}
	if got.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be carried through")
	}
}

// A host app with no geolocator configured is the default case, not a
// degraded one — half a label is the whole feature for them.
func TestListNamed_WithoutAGeolocatorLabelsAreDeviceOnly(t *testing.T) {
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	sessions.Create(ctx, store.Session{
		ID: "s1", FamilyID: "s1", UserID: "user-1",
		IP: "1.2.3.4", UserAgent: safariIPhone,
	})

	list, err := ListNamed(ctx, sessions, nil, noopLogger{}, "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if list[0].Label != "Safari on iOS" {
		t.Errorf("expected a device-only label, got %q", list[0].Label)
	}
	if !list[0].Location.IsZero() {
		t.Errorf("expected no location without a geolocator, got %+v", list[0].Location)
	}
}

// Someone's phone and laptop behind one home address is the normal
// shape of this list, and the host pays per lookup.
func TestListNamed_AsksTheGeolocatorOncePerDistinctIP(t *testing.T) {
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	sessions.Create(ctx, store.Session{ID: "s1", FamilyID: "s1", UserID: "user-1", IP: "1.2.3.4", UserAgent: chromeWindows})
	sessions.Create(ctx, store.Session{ID: "s2", FamilyID: "s2", UserID: "user-1", IP: "1.2.3.4", UserAgent: safariIPhone})
	sessions.Create(ctx, store.Session{ID: "s3", FamilyID: "s3", UserID: "user-1", IP: "5.6.7.8", UserAgent: chromeWindows})
	geo := &stubGeolocator{byIP: map[string]security.Location{
		"1.2.3.4": {City: "San Francisco", Region: "CA"},
		"5.6.7.8": {City: "Berlin", Country: "DE"},
	}}

	list, err := ListNamed(ctx, sessions, geo, noopLogger{}, "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 named sessions, got %d", len(list))
	}
	if geo.calls != 2 {
		t.Errorf("expected 2 lookups for 2 distinct addresses, got %d (%v)", geo.calls, geo.seen)
	}
	// The cached answer must reach the second session too, not just the
	// one that paid for the lookup.
	for _, s := range list {
		if s.IP == "1.2.3.4" && s.Location.City != "San Francisco" {
			t.Errorf("session %s missed the cached location: %+v", s.ID, s.Location)
		}
	}
}

// Fails open, same as a breach-check error never failing SignUp: a
// third-party provider being down must not stop someone seeing the
// devices on their own account — that list is how they revoke an
// attacker's session.
func TestListNamed_GeolocatorErrorDegradesToDeviceOnly(t *testing.T) {
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	sessions.Create(ctx, store.Session{ID: "s1", FamilyID: "s1", UserID: "user-1", IP: "1.2.3.4", UserAgent: chromeWindows})
	sessions.Create(ctx, store.Session{ID: "s2", FamilyID: "s2", UserID: "user-1", IP: "1.2.3.4", UserAgent: chromeWindows})
	geo := &stubGeolocator{err: errors.New("provider unreachable")}

	list, err := ListNamed(ctx, sessions, geo, noopLogger{}, "user-1")
	if err != nil {
		t.Fatalf("a geolocator failure must not fail the listing: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected both sessions, got %d", len(list))
	}
	for _, s := range list {
		if s.Label != "Chrome on Windows" {
			t.Errorf("expected a device-only label after a lookup failure, got %q", s.Label)
		}
	}
	// A failure is cached like any other answer — a broken provider gets
	// asked once, not once per session.
	if geo.calls != 1 {
		t.Errorf("expected the failed lookup not to be retried per session, got %d calls", geo.calls)
	}
}

func TestListNamed_EmptyIPIsNeverLookedUp(t *testing.T) {
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	sessions.Create(ctx, store.Session{ID: "s1", FamilyID: "s1", UserID: "user-1", UserAgent: chromeWindows})
	geo := &stubGeolocator{byIP: map[string]security.Location{"": {City: "Nowhere"}}}

	list, err := ListNamed(ctx, sessions, geo, noopLogger{}, "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if geo.calls != 0 {
		t.Errorf("an empty IP is not an address to place, got %d calls", geo.calls)
	}
	if list[0].Label != "Chrome on Windows" {
		t.Errorf("expected a device-only label, got %q", list[0].Label)
	}
}

// Every session gets a printable row, including one from a client that
// sent no User-Agent at all.
func TestListNamed_UnknownDeviceStillGetsALabel(t *testing.T) {
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	sessions.Create(ctx, store.Session{ID: "s1", FamilyID: "s1", UserID: "user-1", IP: "5.6.7.8"})
	geo := &stubGeolocator{byIP: map[string]security.Location{"5.6.7.8": {City: "Berlin", Country: "DE"}}}

	list, err := ListNamed(ctx, sessions, geo, noopLogger{}, "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if list[0].Label != "Unknown device — Berlin, DE" {
		t.Errorf("unexpected label: %q", list[0].Label)
	}
}

// ListNamed is a labelled List, not a second query with its own rules:
// a caller who switches to it must not silently start seeing revoked
// sessions or other people's.
func TestListNamed_ExcludesRevokedSessionsAndOtherUsers(t *testing.T) {
	ctx := context.Background()
	sessions := memory.NewSessionStore()
	sessions.Create(ctx, store.Session{ID: "s1", FamilyID: "s1", UserID: "user-1", IP: "1.2.3.4", UserAgent: chromeWindows})
	sessions.Create(ctx, store.Session{ID: "s2", FamilyID: "s2", UserID: "user-1", IP: "1.2.3.4", UserAgent: chromeWindows})
	sessions.Create(ctx, store.Session{ID: "s3", FamilyID: "s3", UserID: "user-2", IP: "9.9.9.9", UserAgent: chromeWindows})
	sessions.Revoke(ctx, "s2")

	list, err := ListNamed(ctx, sessions, nil, noopLogger{}, "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 1 || list[0].ID != "s1" {
		t.Fatalf("expected only the active session for user-1, got %+v", list)
	}

	empty, err := ListNamed(ctx, sessions, nil, noopLogger{}, "nobody")
	if err != nil {
		t.Fatalf("an unknown user should not be an error: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected no sessions for an unknown user, got %d", len(empty))
	}
}

func TestLabel(t *testing.T) {
	device := security.Device{Browser: "Firefox", OS: "Linux", Form: security.FormDesktop}
	cases := []struct {
		name     string
		device   security.Device
		location security.Location
		want     string
	}{
		{"both halves", device, security.Location{City: "Lagos", Country: "NG"}, "Firefox on Linux — Lagos, NG"},
		{"no location", device, security.Location{}, "Firefox on Linux"},
		{"no device", security.Device{}, security.Location{Country: "NG"}, "Unknown device — NG"},
		{"neither", security.Device{}, security.Location{}, "Unknown device"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Label(tc.device, tc.location); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
