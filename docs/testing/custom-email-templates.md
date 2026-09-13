# Manual test guide — Custom email templates

**This needed no engine change, and the queue entry said it probably
wouldn't.** The host app already owns every byte of every email the
engine causes to be sent: the subject, the markup, the plain-text
alternative, the link, the domain, the from-address, the language, and
the provider. There is no template in the engine to override and no
template knob on `Config` to set, because the engine never composes an
email — it hands an implementation a recipient and a raw token and stops
there.

So this guide is not "how to configure templates." It is the answer to
the question that led here: *how do I control what these emails say?*

## The whole outward surface

Two interfaces, two methods, two call sites in the entire tree:

| Flow | Interface | Called from | Facade entry point |
| --- | --- | --- | --- |
| Confirm a new email address | `notify.EmailSender` | `auth/email.go:70` | `cryden.RequestEmailChange` |
| Passwordless login link | `notify.MagicLinkSender` | `auth/magiclink.go:88` | `cryden.RequestMagicLink` |

```go
SendVerification(ctx context.Context, to string, rawToken string) error
SendMagicLink(ctx context.Context, to string, rawToken string) error
```

That is everything the engine says. `to` is the address, `rawToken` is
an opaque hex string — 64 characters by default, following
`Config.RefreshTokenByteLength` (32 bytes), since verification tokens
come from the same generator as refresh tokens. The engine builds no
URL: it does not know your routing, your domain, or your scheme.

## Owning the template, in full

One host type can serve both flows. This is the shape the smoke test
runs, cut down:

```go
type mailer struct{ provider *sendgrid.Client }

func (m mailer) SendVerification(ctx context.Context, to, rawToken string) error {
	return m.send(ctx, to, verifyTemplate, map[string]string{
		"URL":     "https://acme.example/settings/email/confirm?token=" + url.QueryEscape(rawToken),
		"Expires": "1 hour",
	}, subjectFor(to, "verify"))
}

func (m mailer) SendMagicLink(ctx context.Context, to, rawToken string) error {
	return m.send(ctx, to, loginTemplate, map[string]string{
		"URL":     "https://acme.example/login/magic?token=" + url.QueryEscape(rawToken),
		"Expires": "15 minutes",
	}, subjectFor(to, "login"))
}
```

Wire both to the same value:

```go
m := mailer{provider: sendgrid.NewClient(os.Getenv("SENDGRID_KEY"))}

engine, err := cryden.New(cryden.Config{
	JWTSecret:     os.Getenv("JWT_SECRET"),
	Users:         users,
	Sessions:      sessions,
	Audit:         audit,
	Verifications: verifications, // required by both flows
	EmailSender:     m,
	MagicLinkSender: m,
})
```

Everything a real email needs and the engine has no opinion about —
MJML or `html/template`, a plain-text part, an unsubscribe footer that
does not belong on a security email, a per-tenant from-address, a locale
chosen from the recipient, a provider chosen from a feature flag — is
already yours, because it is all inside a method you wrote.

## What the engine deliberately does not pass

| Not passed | What to do |
| --- | --- |
| The link's expiry | Hardcode it. `changeEmailTokenTTL` is **1 hour** (`auth/email.go`) and `magicLinkTTL` is **15 minutes** (`auth/magiclink.go`). Both are unexported, and the magic-link one is documented as deliberately not configurable — a login link is a bearer credential, and its lifetime is not a tuning knob |
| The user's ID or display name | Look it up yourself if you want it, but consider not wanting it for the change-of-address email: that address is unconfirmed and may be a typo, so personalising from account data puts account details in front of whoever actually owns it |
| The old email address | Same reasoning, more strongly. Do not put it in the email going to the new address |
| The language | Pick it from the recipient, the account, or your own request context — all data you have and the engine does not |
| Which flow it is | You do not need it told: the two interfaces have separate methods precisely so `"confirm your new email"` and `"click to log in"` are two functions you write separately (`notify/magic_link_sender.go` says so at length) |

If a template must state the expiry, the honest options are to hardcode
it — with a test that checks the number, as the smoke test's section
nine does by reading `ExpiresAt` back out of your own
`VerificationStore` — or to open an engine item to export the two
constants. The second is a real API commitment, so it is not done
speculatively here; see "Known limits".

## Things your copy must not promise

- **An unknown address sends nothing.** `RequestMagicLink` returns `nil`
  for an address with no account, and calls no sender, so that account
  enumeration is not a feature of the login page. Your "check your
  inbox" screen is therefore your claim, not the engine's guarantee.
- **A send failure fails the operation.** If `SendVerification` returns
  an error, `RequestEmailChange` returns it and the address does not
  change. The user should be told the email did not go out, not that it
  did.
- **Links are single-use and purpose-bound.** A second
  `ConfirmEmailChange` with the same token is
  `auth.ErrVerificationTokenInvalid`, and a magic-link token will not
  confirm an email change or the reverse.
- **The token in the link is a live credential.** Do not log the
  composed URL, do not put it in an analytics event, and do not let a
  provider's click-tracking rewrite it into a URL you cannot verify.
- **Nothing tells you an email was sent, by default.** The engine
  records `email_change_requested` and `magic_link_requested` audit
  events, and neither is in `cryden.DefaultWebhookEvents()` — add them
  to `Config.WebhookEvents` explicitly if a host system needs to know.

## Running it

```
go test ./...
go run ./cmd/smoketest/custom-email-templates
```

Nothing here contacts a mail provider. The smoke test writes a real host
mailer — `html/template` bodies, an English and a German copy deck, two
provider labels — and runs 54 checks over ten sections:

1. **What the engine hands the host app** — one email, addressed to the
   new address, carrying a 64-char hex token, with a subject and body
   that came entirely from the host's own copy deck and mention the
   engine nowhere.
2. **A link the host built round-trips into the engine** — the token is
   pulled back out of the composed HTML, as a browser would, and
   confirms the change; the account moves, the old address stops
   resolving, and the link refuses a second use.
3. **Two flows, two templates, no ambiguity** — the login email uses the
   login template, is worded nothing like the confirmation email, and
   its token signs the user in through `CompleteMagicLink`.
4. **The same interface, any provider** — the provider label changes
   between two sends and the engine's half of the payload does not.
5. **A template chosen per recipient** — a `.de` address gets the German
   subject and body, from data the host already had.
6. **There is no template knob on Config to set** — by reflection:
   `Config`'s only email-shaped fields are `EmailSender` and
   `MagicLinkSender`, both interfaces, and each has exactly one method
   taking `(context.Context, string, string) error`.
7. **A provider failure is the host's error, and nothing
   half-happens** — the send error reaches the caller unchanged and the
   address does not change.
8. **An unknown address sends nothing at all** — no error, no call.
9. **What the engine does not tell the sender** — the real TTLs read
   back out of the host's own `VerificationStore` (15 minutes and 1
   hour), checked against the strings the templates hardcode.
10. **What is actually sent** — all three composed emails printed in
    full, plus a check that no email anywhere contains the password.

The same verdict is pinned in `go test ./...` by
`custom_email_templates_test.go`, so a `Config.EmailSubject` added in
some future session fails the suite rather than quietly making this
guide wrong.

### Trying it by hand

Wire a sender that only prints, request a change, and read what comes
out — the point is that all of it is yours:

```go
type printSender struct{}

func (printSender) SendVerification(_ context.Context, to, rawToken string) error {
	fmt.Printf("To: %s\nSubject: whatever you like\n\nhttps://your.app/x?token=%s\n", to, rawToken)
	return nil
}
```

Then paste the token into `cryden.ConfirmEmailChange` and watch the
address move. Then have it `return errors.New("nope")` and watch
`RequestEmailChange` fail with that error and the address stay put.

## Postgres and SQLite

Nothing to run. No schema change, no migration, no store change — the
`verification_tokens` table both flows already use is unchanged.

## Known limits

These are the things a host might genuinely want and cannot have today.
None of them is "the template," and none was built speculatively:

- **The TTLs are not discoverable through the interface.** A template
  that says "expires in 1 hour" hardcodes a number that lives in an
  unexported constant, and would drift silently if the constant changed.
  Exporting `cryden.EmailChangeTokenTTL` and `cryden.MagicLinkTokenTTL`
  would fix it in about four lines and is the one engine change worth
  queueing if this matters to you. Adding a parameter to either send
  method would not: that breaks every existing host implementation at
  compile time, which is exactly why `MagicLinkSender` was a new
  interface instead of a second method on `EmailSender`.
- **There is no signup email-verification flow.** `SignUp` sends nothing
  and `store.PurposeEmailVerify` exists without a producer, so there is
  no third template to write. A host that wants "verify your address
  before you can log in" builds it on `RequestEmailChange`'s pattern
  today, or the engine gains the flow later.
- **There is no password-reset email**, because there is no
  password-reset flow — `ChangePassword` requires the current password,
  and forgot-password is the host's to build (magic-link login plus
  `ChangePassword` is the usual composition).
- **No retries, no queue, no dedupe.** `SendVerification` is called once,
  synchronously, on the request path; the operation fails if it fails.
  Enqueue inside your implementation if you need durability, the same
  advice `docs/testing/webhooks.md` gives for the same reason.
- **No engine-side rate limit on the email-change flow.**
  `RequestMagicLink` is limited (`magic-link:<ip>:<email>`),
  `RequestEmailChange` is not — it needs an authenticated user ID, so it
  is not an open endpoint, but nothing stops a logged-in account from
  requesting many. Limit it at your handler if that matters.
- **One implementation per flow.** Two brands or two locales are a
  branch inside your method, not two `Config` fields.
