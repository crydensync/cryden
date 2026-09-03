package notify

import "context"

// MagicLinkSender delivers passwordless login links. Deliberately a
// separate interface from EmailSender rather than a new method added
// to it — EmailSender already shipped in an earlier release, and
// adding a required method to an existing interface would break every
// consuming app's existing implementation at compile time. The two
// are also genuinely different concerns for the app to word
// differently: "confirm your new email" reads nothing like "click to
// log in," and EmailSender.SendVerification has no way to signal
// which one it's sending.
type MagicLinkSender interface {
	// SendMagicLink delivers rawToken to `to`. As with
	// EmailSender.SendVerification, building the actual clickable URL
	// is the caller's job — the engine doesn't know your routing.
	SendMagicLink(ctx context.Context, to string, rawToken string) error
}
