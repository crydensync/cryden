package security

import (
	"context"
	"strings"
)

// Location is a coarse, human-readable place derived from an IP
// address — the "San Francisco, CA" half of a session label like
// "Chrome on Windows — San Francisco, CA".
//
// Every field is optional, and String() simply omits the empty ones,
// which is how granularity is chosen: a host serving one country
// returns City+Region and gets "San Francisco, CA", a host serving
// many returns Country too and gets "San Francisco, CA, US". The
// engine formats exactly what its IPGeolocator hands over and never
// invents, expands or abbreviates a field.
type Location struct {
	City    string
	Region  string // state, province or region — whatever the host's data has
	Country string
}

// IsZero reports whether no part of the location is known. A
// geolocator that cannot place an address should return the zero
// Location rather than an error, which is not an anomaly: private,
// reserved and carrier-NAT addresses are routinely unplaceable.
func (l Location) IsZero() bool {
	return strings.TrimSpace(l.City) == "" &&
		strings.TrimSpace(l.Region) == "" &&
		strings.TrimSpace(l.Country) == ""
}

// String joins the non-empty fields with ", " — "San Francisco, CA,
// US", "Berlin, DE", "US", or "" when nothing is known.
func (l Location) String() string {
	parts := make([]string, 0, 3)
	for _, part := range []string{l.City, l.Region, l.Country} {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return strings.Join(parts, ", ")
}

// IPGeolocator resolves an IP address to a coarse Location for
// display in a session list. Like BreachedPasswordChecker and
// EmailSender/MagicLinkSender, this ships zero production
// implementations — placing an address means either an outbound
// network call or a licensed geo-IP database on disk, and the engine
// neither talks to the internet on its own initiative nor takes on
// third-party data files, so it doesn't start here either. The
// consuming app implements this against MaxMind, ipinfo, its CDN's
// own edge headers, or anything else that fits.
//
// This is the one half of a session label the engine structurally
// cannot compute for itself: the device half comes from
// ParseUserAgent, which needs nothing but the string already stored on
// the session.
type IPGeolocator interface {
	// Locate resolves ip to a Location. Return the zero Location with
	// a nil error for an address that is simply unplaceable (private
	// range, carrier NAT, unknown); return an error only when the
	// lookup itself failed, e.g. the provider was unreachable.
	//
	// Either way the session label degrades to its device half and the
	// call that asked for it still succeeds — session listing fails
	// open on a geolocator error, for the same reason SignUp fails
	// open on a breach-check error: a third-party provider's uptime
	// should not decide whether someone can see their own devices.
	Locate(ctx context.Context, ip string) (Location, error)
}
