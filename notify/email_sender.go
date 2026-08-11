package notify

import "context"

// EmailSender defines email delivery for verification flows. Like
// Logger, this is an interface only — the engine never sends email
// itself, never calls a provider API, and never leaves the consuming
// app's infrastructure. The consuming app wires an implementation
// (SendGrid, SES, SMTP, whatever) and owns the actual email template
// and the verification URL/domain — the engine only hands over a raw
// token, it has no idea what your app's domain is.
type EmailSender interface {
	// SendVerification delivers rawToken to `to`. It's the caller's
	// job to build the actual clickable URL (e.g.
	// https://yourapp.com/verify?token=rawToken) — the engine never
	// constructs URLs, it doesn't know your routing.
	SendVerification(ctx context.Context, to string, rawToken string) error
}
