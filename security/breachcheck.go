package security

import "context"

// BreachedPasswordChecker defines a check for whether a password has
// appeared in a known data breach. Like EmailSender/MagicLinkSender,
// this ships zero production implementations — checking this
// necessarily means an outbound network call (e.g. to HIBP's
// k-anonymity API), and the engine never talks to the internet on its
// own initiative anywhere else, so it doesn't start here either. The
// consuming app implements this against HIBP, a self-hosted breached-
// password list, or anything else that fits.
type BreachedPasswordChecker interface {
	// IsBreached reports whether password has appeared in a known
	// breach. A non-nil error means the check itself failed (e.g. the
	// host's HIBP integration is unreachable) — callers should treat
	// that as "unknown," not "breached": SignUp/ChangePassword fail
	// open on a checker error, since blocking account creation on a
	// third-party API's uptime is a worse tradeoff than the security
	// gained.
	IsBreached(ctx context.Context, password string) (bool, error)
}
