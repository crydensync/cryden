package session

import (
	"context"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
)

// NamedSession is an active session plus a human-readable description
// of where it came from — what a "your devices" settings page shows
// instead of a raw session ID.
//
// It embeds store.PublicSession rather than store.Session, so the
// redacted set of fields (no TokenHash, no FamilyID) is what reaches a
// UI, and the raw IP/UserAgent stay available for a host app that
// wants to render them itself. Device and Location are kept alongside
// Label so a caller can format its own string (or sort/group by OS,
// form factor or country) without re-parsing anything.
type NamedSession struct {
	store.PublicSession
	Device   security.Device
	Location security.Location
	Label    string
}

// Label composes the display string for a session: "Chrome on Windows
// — San Francisco, CA", or just "Chrome on Windows" when the location
// is unknown, or "Unknown device" when the User-Agent was unparseable
// too. Never returns an empty string.
//
// Exported because the location half is host-supplied: an app that
// resolves richer location data at its own layer, or none at all, can
// still produce labels identical to the engine's.
func Label(device security.Device, location security.Location) string {
	name := device.String()
	if location.IsZero() {
		return name
	}
	return name + " — " + location.String()
}

// ListNamed returns a user's active sessions with a device/location
// label attached to each. Same set of sessions as List, in the same
// order — labels are computed on read from the IP and User-Agent the
// session already carries, so nothing is stored, no migration exists
// for this, and every session ever recorded gets a label the moment
// this is called.
//
// geo is optional. Left nil, labels are device-only. Supplied, it is
// asked once per distinct IP in the list (several sessions from one
// address is the normal case) and its answers are used as-is. A
// geolocator error is logged and treated as "location unknown" — the
// listing itself never fails because of it, matching how a breach-
// check error never fails SignUp.
func ListNamed(
	ctx context.Context,
	sessions store.SessionStore,
	geo security.IPGeolocator,
	log logger.Logger,
	userID string,
) ([]NamedSession, error) {
	list, err := List(ctx, sessions, userID)
	if err != nil {
		return nil, err
	}

	located := make(map[string]security.Location, len(list))
	out := make([]NamedSession, 0, len(list))
	for _, s := range list {
		device := security.ParseUserAgent(s.UserAgent)

		var location security.Location
		// An empty IP is not an address to place, and a repeated one is
		// not a second question to ask. The cache is per call, not per
		// process: sessions are long-lived but a location can change
		// hands, and caching across calls would need an invalidation
		// story this feature does not need to have.
		if geo != nil && s.IP != "" {
			cached, ok := located[s.IP]
			if !ok {
				resolved, locErr := geo.Locate(ctx, s.IP)
				if locErr != nil {
					log.Warn("session list: geolocation failed", map[string]string{
						"error":   locErr.Error(),
						"user_id": userID,
						"ip":      s.IP,
					})
					resolved = security.Location{}
				}
				cached = resolved
				located[s.IP] = cached
			}
			location = cached
		}

		out = append(out, NamedSession{
			PublicSession: s.ToPublic(),
			Device:        device,
			Location:      location,
			Label:         Label(device, location),
		})
	}
	return out, nil
}
