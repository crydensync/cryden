// Command named-sessions is a standalone, no-database smoke test for
// named/fingerprinted sessions: the label a "your devices" page shows
// for each active session, one geolocation lookup per distinct address,
// what happens when no geolocator is configured or the one configured
// fails, bots and clients that send no User-Agent at all, and the
// property the design rests on — labels are computed on read, so a
// session recorded before any of this existed still gets one. Run with:
//
//	go run ./cmd/smoketest/named-sessions
package main

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store/memory"
)

const (
	email    = "raymondproguy@dev.com"
	password = "Tr0ubl3-Fr33!2026"

	homeIP   = "1.2.3.4"
	officeIP = "203.0.113.7"

	// Authentic strings, because the labels below are only meaningful
	// if the input is what a real client actually sends.
	chromeWindows = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	safariIPhone  = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
	firefoxLinux  = "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
	curlAgent     = "curl/8.6.0"
)

var failures int

// countingGeolocator is the implementation a host app would supply,
// plus a call counter — "asked once per distinct IP" is a promise the
// host pays for, so it is worth checking from the outside.
type countingGeolocator struct {
	byIP  map[string]security.Location
	err   error
	calls int
}

func (g *countingGeolocator) Locate(_ context.Context, ip string) (security.Location, error) {
	g.calls++
	if g.err != nil {
		return security.Location{}, g.err
	}
	return g.byIP[ip], nil
}

func knownAddresses() *countingGeolocator {
	return &countingGeolocator{byIP: map[string]security.Location{
		homeIP:   {City: "San Francisco", Region: "CA"},
		officeIP: {City: "Berlin", Country: "DE"},
	}}
}

// rig is one isolated engine plus the pieces the checks read back from.
// The stores are held so one scenario can build a second engine over
// the same data.
type rig struct {
	engine   *cryden.Engine
	users    *memory.UserStore
	sessions *memory.SessionStore
	geo      *countingGeolocator
	userID   string
}

func newRig(ctx context.Context, geo *countingGeolocator) (*rig, error) {
	r := &rig{
		users:    memory.NewUserStore(),
		sessions: memory.NewSessionStore(),
		geo:      geo,
	}
	cfg := cryden.Config{
		JWTSecret: "smoketest-jwt-secret",
		Users:     r.users,
		Sessions:  r.sessions,
		Audit:     memory.NewAuditStore(),
		// Several logins from one address in a row is the normal shape of
		// this test, not an attack.
		RateLimitAttempts: 1000,
	}
	// Assigned only when non-nil: a typed nil pointer in an interface
	// field is not a nil interface, and would be called anyway.
	if geo != nil {
		cfg.Geolocator = geo
	}
	engine, err := cryden.New(cfg)
	if err != nil {
		return nil, err
	}
	r.engine = engine

	user, err := cryden.SignUp(ctx, engine, email, password, homeIP)
	if err != nil {
		return nil, err
	}
	r.userID = user.ID
	return r, nil
}

func (r *rig) login(ctx context.Context, ip, userAgent string) error {
	_, err := cryden.Login(ctx, r.engine, email, password, ip, userAgent)
	return err
}

func (r *rig) named(ctx context.Context) []cryden.NamedSession {
	list, err := cryden.ListNamedSessions(ctx, r.engine, r.userID)
	if err != nil {
		fail(fmt.Sprintf("listing named sessions: %v", err))
		return nil
	}
	return list
}

// labels returns every session's label, sorted, so a scenario can
// assert on the set without depending on store ordering.
func (r *rig) labels(ctx context.Context) []string { return labelsOf(r.named(ctx)) }

// labelsOf is the same over a listing already in hand — which matters
// wherever lookup counts are being checked, since the geolocation cache
// is per call and a second listing legitimately asks again.
func labelsOf(list []cryden.NamedSession) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, s.Label)
	}
	sort.Strings(out)
	return out
}

func main() {
	ctx := context.Background()

	labelsARealLogin(ctx)
	severalDevicesOneAccount(ctx)
	withoutAGeolocator(ctx)
	failingGeolocator(ctx)
	unrecognizedClients(ctx)
	revokedSessionsDisappear(ctx)
	labelsAreComputedNotStored(ctx)

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
		return
	}
	fmt.Printf("%d CHECK(S) FAILED\n", failures)
	os.Exit(1)
}

// The straight-line case: one login, one labelled row.
func labelsARealLogin(ctx context.Context) {
	section("a login from a browser gets a device and a location")
	r, err := newRig(ctx, knownAddresses())
	if err != nil {
		fail(fmt.Sprintf("building the engine: %v", err))
		return
	}
	check("logged in from a Chrome-on-Windows browser", r.login(ctx, homeIP, chromeWindows))

	list := r.named(ctx)
	expectCount("one active session is listed", len(list), 1)
	if len(list) != 1 {
		return
	}
	s := list[0]
	expectString("its label reads as a person would recognize it", s.Label, "Chrome on Windows — San Francisco, CA")
	expectString("the browser was parsed out", s.Device.Browser, "Chrome")
	expectString("the OS was parsed out", s.Device.OS, "Windows")
	expectString("the form factor was parsed out", s.Device.Form, security.FormDesktop)
	expectString("the city came from the host's geolocator", s.Location.City, "San Francisco")
	expectString("the region came with it", s.Location.Region, "CA")

	// The raw values stay exposed: the label is an addition, not a
	// replacement, and a host app can render its own.
	expectString("the raw IP is still available", s.IP, homeIP)
	expectString("the raw User-Agent is still available", s.UserAgent, chromeWindows)
	if s.ID == "" {
		fail("the session ID is needed to revoke this row and was empty")
	} else {
		pass("the session ID is present, so the row is actionable")
	}
	if s.CreatedAt.IsZero() {
		fail("CreatedAt was zero, so the row cannot be sorted by recency")
	} else {
		pass("CreatedAt came through")
	}
	expectCount("the geolocator was asked exactly once", r.geo.calls, 1)
}

// Two devices at home, one at the office: the realistic list, and the
// one that proves lookups are per address rather than per session.
func severalDevicesOneAccount(ctx context.Context) {
	section("several devices on one account")
	r, err := newRig(ctx, knownAddresses())
	if err != nil {
		fail(fmt.Sprintf("building the engine: %v", err))
		return
	}
	check("logged in from the laptop at home", r.login(ctx, homeIP, chromeWindows))
	check("logged in from the phone on the same connection", r.login(ctx, homeIP, safariIPhone))
	check("logged in from a Linux machine at the office", r.login(ctx, officeIP, firefoxLinux))

	list := r.named(ctx)
	expectLabels("all three sessions are labelled distinctly", labelsOf(list),
		"Chrome on Windows — San Francisco, CA",
		"Firefox on Linux — Berlin, DE",
		"Safari on iOS — San Francisco, CA",
	)
	expectCount("two distinct addresses cost two lookups, not three", r.geo.calls, 2)

	// Form factor is what a UI groups by ("phones", "computers"), so
	// check it survived on the phone specifically.
	for _, s := range list {
		if s.Device.OS == "iOS" {
			expectString("the phone is marked as a mobile device", s.Device.Form, security.FormMobile)
		}
	}
}

// No geolocator configured is the default, and half a label is the
// whole feature for a host that never wires one up.
func withoutAGeolocator(ctx context.Context) {
	section("no geolocator configured")
	r, err := newRig(ctx, nil)
	if err != nil {
		fail(fmt.Sprintf("building the engine: %v", err))
		return
	}
	check("logged in from the laptop", r.login(ctx, homeIP, chromeWindows))
	check("logged in from the phone", r.login(ctx, homeIP, safariIPhone))

	expectLabels("labels are device-only and still useful", r.labels(ctx),
		"Chrome on Windows",
		"Safari on iOS",
	)
	for _, s := range r.named(ctx) {
		if !s.Location.IsZero() {
			fail(fmt.Sprintf("expected no location without a geolocator, got %+v", s.Location))
			return
		}
	}
	pass("no location was invented for any session")
}

// Negative case, and the important one: this listing is how someone
// revokes a session they do not recognize, so a broken third-party
// provider must not be able to take it away from them.
func failingGeolocator(ctx context.Context) {
	section("the host's geolocator is down")
	geo := knownAddresses()
	geo.err = fmt.Errorf("geo provider unreachable")
	r, err := newRig(ctx, geo)
	if err != nil {
		fail(fmt.Sprintf("building the engine: %v", err))
		return
	}
	check("logged in from the laptop", r.login(ctx, homeIP, chromeWindows))
	check("logged in from the phone on the same connection", r.login(ctx, homeIP, safariIPhone))

	list := r.named(ctx)
	expectCount("the listing still returns every session", len(list), 2)
	expectLabels("labels degrade to their device half", labelsOf(list),
		"Chrome on Windows",
		"Safari on iOS",
	)
	expectCount("one listing asked once, not once per session on the address", geo.calls, 1)
}

// A client that sends nothing, and one that is plainly not a person's
// browser. Both must produce an honest row rather than a blank or a
// guess.
func unrecognizedClients(ctx context.Context) {
	section("clients that are not a browser")
	r, err := newRig(ctx, knownAddresses())
	if err != nil {
		fail(fmt.Sprintf("building the engine: %v", err))
		return
	}
	check("logged in sending no User-Agent at all", r.login(ctx, homeIP, ""))
	check("logged in from a command-line client", r.login(ctx, homeIP, curlAgent))

	expectLabels("both get an honest, printable label", r.labels(ctx),
		"Unknown device — San Francisco, CA",
		"curl — San Francisco, CA",
	)
	for _, s := range r.named(ctx) {
		if s.Device.Browser == "curl" {
			expectString("the command-line client is marked as a bot, not a browser", s.Device.Form, security.FormBot)
			expectString("and no OS is claimed for it", s.Device.OS, "")
		}
	}
}

// Revoking is the action the whole list exists for, so the revoked row
// must actually leave it.
func revokedSessionsDisappear(ctx context.Context) {
	section("revoking the session you do not recognize")
	r, err := newRig(ctx, knownAddresses())
	if err != nil {
		fail(fmt.Sprintf("building the engine: %v", err))
		return
	}
	check("logged in from the laptop", r.login(ctx, homeIP, chromeWindows))
	check("logged in from an unfamiliar machine at another address", r.login(ctx, officeIP, firefoxLinux))

	list := r.named(ctx)
	expectCount("both sessions are listed", len(list), 2)

	var target string
	for _, s := range list {
		if s.Location.City == "Berlin" {
			target = s.ID
		}
	}
	if target == "" {
		fail("could not find the unfamiliar session to revoke")
		return
	}
	check("revoked it by the ID from its own row", cryden.RevokeSession(ctx, r.engine, target, r.userID))
	expectLabels("only the familiar session remains", r.labels(ctx),
		"Chrome on Windows — San Francisco, CA",
	)
}

// The design claim, checked end to end: nothing about a label is
// stored, so a session recorded by an engine with no geolocator gets a
// located label the moment one is configured — no migration, no
// backfill, no re-login.
func labelsAreComputedNotStored(ctx context.Context) {
	section("labels are computed on read, never stored")
	r, err := newRig(ctx, nil)
	if err != nil {
		fail(fmt.Sprintf("building the engine: %v", err))
		return
	}
	check("logged in while no geolocator was configured", r.login(ctx, homeIP, chromeWindows))
	expectLabels("the label has no location, as expected", r.labels(ctx), "Chrome on Windows")

	// A second engine over the same stores — what deploying a
	// geolocator later actually looks like.
	geo := knownAddresses()
	upgraded, err := cryden.New(cryden.Config{
		JWTSecret:         "smoketest-jwt-secret",
		Users:             r.users,
		Sessions:          r.sessions,
		Audit:             memory.NewAuditStore(),
		Geolocator:        geo,
		RateLimitAttempts: 1000,
	})
	if err != nil {
		fail(fmt.Sprintf("building the upgraded engine: %v", err))
		return
	}
	list, err := cryden.ListNamedSessions(ctx, upgraded, r.userID)
	if err != nil {
		fail(fmt.Sprintf("listing from the upgraded engine: %v", err))
		return
	}
	expectCount("the same stored session is still there", len(list), 1)
	if len(list) != 1 {
		return
	}
	expectString("and now carries a location, with nothing re-recorded", list[0].Label,
		"Chrome on Windows — San Francisco, CA")
}

func section(name string) {
	fmt.Printf("\n— %s\n", name)
}

func expectLabels(step string, got []string, want ...string) {
	if len(got) != len(want) {
		fail(fmt.Sprintf("%s: expected %d label(s) %v, got %d %v", step, len(want), want, len(got), got))
		return
	}
	for i := range want {
		if got[i] != want[i] {
			fail(fmt.Sprintf("%s: label %d was %q, want %q", step, i+1, got[i], want[i]))
			return
		}
	}
	pass(step)
}

func expectString(step, got, want string) {
	if got != want {
		fail(fmt.Sprintf("%s: got %q, want %q", step, got, want))
		return
	}
	pass(step)
}

func expectCount(step string, got, want int) {
	if got != want {
		fail(fmt.Sprintf("%s: got %d, want %d", step, got, want))
		return
	}
	pass(step)
}

func check(step string, err error) {
	if err != nil {
		fail(fmt.Sprintf("%s: unexpected error: %v", step, err))
		return
	}
	pass(step)
}

func pass(step string) {
	fmt.Println("✓", step)
}

func fail(msg string) {
	failures++
	fmt.Println("✗", msg)
}
