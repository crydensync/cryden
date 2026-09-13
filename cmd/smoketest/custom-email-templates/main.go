// Command custom-email-templates is a standalone, no-database smoke
// test for a claim rather than a feature: the host app already owns
// every byte of every email the engine causes to be sent. Nothing in
// the engine composes a subject, a body, a link or a from-address, and
// there is no template knob on Config to set — so there is nothing to
// make customisable. This test proves that by writing a real host-side
// mailer, with real HTML templates and two languages, and showing the
// engine accepts what comes out of it. Run with:
//
//	go run ./cmd/smoketest/custom-email-templates
package main

import (
	"context"
	"errors"
	"fmt"
	"html"
	"html/template"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/auth"
	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/notify"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"
)

const (
	email       = "raymondproguy@dev.com"
	password    = "Tr0ubl3-Fr33!2026"
	newEmail    = "ray@acme.example"
	germanEmail = "ray@acme.de"
)

// The two TTLs the engine actually applies, hardcoded here exactly as a
// host app has to hardcode them: they live in unexported constants
// (auth.changeEmailTokenTTL, auth.magicLinkTTL) and are not handed to
// the sender. Section nine checks these strings against the engine's
// real behaviour, so this file fails loudly rather than drifting if a
// constant ever moves.
const (
	verifyExpires = "1 hour"
	loginExpires  = "15 minutes"
)

var failures int

// wording is the host app's copy deck. Not configuration the engine
// reads — a variable in the host's own binary, which is the entire
// point of this test.
type wording struct{ subject, greeting, lede, action string }

var copyBook = map[string]map[string]wording{
	"en": {
		"verify": {"Confirm your new Acme address", "Almost there", "Confirm this address to finish moving your Acme account to it.", "Confirm this address"},
		"login":  {"Your Acme login link", "Welcome back", "No password needed — the link below signs you straight in.", "Log in to Acme"},
	},
	"de": {
		"verify": {"Bestätige deine neue Acme-Adresse", "Fast fertig", "Bestätige diese Adresse, um dein Acme-Konto darauf umzustellen.", "Adresse bestätigen"},
		"login":  {"Dein Acme-Login-Link", "Willkommen zurück", "Kein Passwort nötig — der Link unten meldet dich direkt an.", "Bei Acme anmelden"},
	},
}

// emailBody is the host's template, in the host's templating engine, on
// the host's domain. The engine has never seen any of it.
var emailBody = template.Must(template.New("email").Parse(
	`<h1>{{.Greeting}}</h1>
<p>{{.Lede}}</p>
<p><a href="{{.URL}}">{{.Action}}</a></p>
<p>This link stops working in {{.Expires}}. Sent to {{.To}}.</p>
<p>— The Acme team</p>`))

// delivery is one email the host decided to send. Only To and Token
// came from the engine; every other field was composed above.
type delivery struct {
	kind, to, token, subject, body, locale, provider, expires string
}

// acmeMailer implements BOTH notify.EmailSender and
// notify.MagicLinkSender — one host type, two flows, two templates,
// with the engine unable to tell that either exists.
type acmeMailer struct {
	provider string
	failWith error
	sent     []delivery
}

func (m *acmeMailer) SendVerification(_ context.Context, to, rawToken string) error {
	return m.compose("verify", to, rawToken, "https://acme.example/settings/email/confirm", verifyExpires)
}

func (m *acmeMailer) SendMagicLink(_ context.Context, to, rawToken string) error {
	return m.compose("login", to, rawToken, "https://acme.example/login/magic", loginExpires)
}

func (m *acmeMailer) compose(kind, to, rawToken, base, expires string) error {
	if m.failWith != nil {
		return m.failWith
	}
	locale := localeFor(to)
	w := copyBook[locale][kind]
	link := base + "?token=" + url.QueryEscape(rawToken)

	var body strings.Builder
	if err := emailBody.Execute(&body, map[string]string{
		"Greeting": w.greeting, "Lede": w.lede, "Action": w.action,
		"URL": link, "Expires": expires, "To": to,
	}); err != nil {
		return err
	}

	m.sent = append(m.sent, delivery{
		kind: kind, to: to, token: rawToken, subject: w.subject,
		body: body.String(), locale: locale, provider: m.provider,
		expires: expires,
	})
	return nil
}

func (m *acmeMailer) last() delivery { return m.sent[len(m.sent)-1] }
func (m *acmeMailer) count() int     { return len(m.sent) }
func (m *acmeMailer) reset()         { m.sent = nil; m.failWith = nil }

// localeFor is the host picking a template from data the host already
// has. The engine is not asked and does not know.
func localeFor(to string) string {
	if strings.HasSuffix(to, ".de") {
		return "de"
	}
	return "en"
}

var _ notify.EmailSender = (*acmeMailer)(nil)
var _ notify.MagicLinkSender = (*acmeMailer)(nil)

// harness is one engine wired to one host mailer, with the stores kept
// so the test can read what the engine wrote.
type harness struct {
	engine        *cryden.Engine
	mailer        *acmeMailer
	verifications *memory.VerificationStore
	users         *memory.UserStore
}

func newHarness(provider string) *harness {
	mailer := &acmeMailer{provider: provider}
	users := memory.NewUserStore()
	verifications := memory.NewVerificationStore()
	engine, err := cryden.New(cryden.Config{
		JWTSecret:     "smoketest-jwt-secret",
		Users:         users,
		Sessions:      memory.NewSessionStore(),
		Audit:         memory.NewAuditStore(),
		Verifications: verifications,
		// The only two email-shaped fields on Config, and both take an
		// interface. Section six proves there are no others.
		EmailSender:       mailer,
		MagicLinkSender:   mailer,
		RateLimitAttempts: 1000,
		Logger:            logger.NewNopLogger(),
	})
	if err != nil {
		fail("engine construction: " + err.Error())
		os.Exit(1)
	}
	if _, err := cryden.SignUp(context.Background(), engine, email, password, "1.2.3.4"); err != nil {
		fail("signup: " + err.Error())
		os.Exit(1)
	}
	return &harness{engine: engine, mailer: mailer, verifications: verifications, users: users}
}

func main() {
	ctx := context.Background()

	section("What the engine hands the host app")
	h := newHarness("smtp-shaped")
	userID := userIDFor(ctx, h, email)
	check("email change requested", cryden.RequestEmailChange(ctx, h.engine, userID, newEmail))
	expectCount("exactly one email was sent", h.mailer.count(), 1)
	d := h.mailer.last()
	expectString("addressed to the new address", d.to, newEmail)
	expectTrue("the engine supplied a 64-char hex token", len(d.token) == 64 && isHex(d.token))
	expectString("the subject is the host's own copy", d.subject, copyBook["en"]["verify"].subject)
	expectTrue("the body is the host's HTML on the host's domain",
		strings.Contains(d.body, "https://acme.example/settings/email/confirm"))
	expectTrue("the token is in the body only because the host put it there",
		strings.Contains(d.body, d.token))
	// The engine contributed two strings. It never named itself, never
	// wrote a subject, never built the URL.
	expectTrue("nothing the engine wrote appears in the email",
		!strings.Contains(strings.ToLower(d.subject+d.body), "cryden"))

	section("A link the host built round-trips into the engine")
	raw, err := linkToken(d.body)
	check("the token extracted back out of the host's own HTML", err)
	expectString("it is the token the engine handed over", raw, d.token)
	check("the change confirmed through the host's link", cryden.ConfirmEmailChange(ctx, h.engine, raw))
	moved, err := cryden.GetUser(ctx, h.engine, newEmail)
	check("the account now answers to the new address", err)
	expectString("and it is the same account", moved.ID, userID)
	_, err = cryden.GetUser(ctx, h.engine, email)
	expectErrorIs("the old address is gone", err, store.ErrNotFound)
	expectErrorIs("the link is single-use",
		cryden.ConfirmEmailChange(ctx, h.engine, raw), auth.ErrVerificationTokenInvalid)

	section("Two flows, two templates, no ambiguity about which is which")
	h2 := newHarness("smtp-shaped")
	check("magic link requested", cryden.RequestMagicLink(ctx, h2.engine, email, "1.2.3.4"))
	login := h2.mailer.last()
	expectString("the login email used the login template", login.kind, "login")
	expectString("with its own subject", login.subject, copyBook["en"]["login"].subject)
	expectTrue("worded nothing like the address-confirmation email",
		login.subject != copyBook["en"]["verify"].subject &&
			!strings.Contains(login.body, copyBook["en"]["verify"].action))
	loginToken, err := linkToken(login.body)
	check("the login token extracted from the host's HTML", err)
	tokens, err := cryden.CompleteMagicLink(ctx, h2.engine, loginToken, "1.2.3.4", "smoketest")
	check("the host-built login link signed the user in", err)
	subject, err := cryden.VerifyToken(h2.engine, tokens.AccessToken)
	check("the access token verifies", err)
	expectString("as the right user", subject, userIDFor(ctx, h2, email))

	section("The same interface, any provider")
	h2.mailer.provider = "sendgrid-shaped"
	check("a second link requested through a different provider",
		cryden.RequestMagicLink(ctx, h2.engine, email, "1.2.3.4"))
	second := h2.mailer.last()
	expectString("the host's provider changed", second.provider, "sendgrid-shaped")
	expectString("the engine's behaviour did not", second.kind, login.kind)
	expectTrue("same shape of token, same recipient, no provider knowledge anywhere",
		second.to == login.to && len(second.token) == 64 && isHex(second.token) && second.token != login.token)

	section("A template chosen per recipient, by the host")
	if _, err := cryden.SignUp(ctx, h2.engine, germanEmail, password, "1.2.3.4"); err != nil {
		fail("german signup: " + err.Error())
	}
	check("magic link requested for a .de address",
		cryden.RequestMagicLink(ctx, h2.engine, germanEmail, "1.2.3.4"))
	german := h2.mailer.last()
	expectString("the host picked its German template", german.locale, "de")
	expectString("with the German subject", german.subject, copyBook["de"]["login"].subject)
	expectTrue("and German body copy", strings.Contains(german.body, copyBook["de"]["login"].greeting))
	expectTrue("from data the host already had, never passed by the engine",
		german.to == germanEmail && len(german.token) == 64)

	section("There is no template knob on Config to set")
	var emailish []string
	cfgType := reflect.TypeOf(cryden.Config{})
	for i := 0; i < cfgType.NumField(); i++ {
		f := cfgType.Field(i)
		lower := strings.ToLower(f.Name)
		for _, needle := range []string{"email", "mail", "sender", "template", "subject", "body", "smtp", "html"} {
			if strings.Contains(lower, needle) {
				emailish = append(emailish, fmt.Sprintf("%s %s", f.Name, f.Type.Kind()))
				break
			}
		}
	}
	fmt.Printf("  Config fields: %s\n", strings.Join(emailish, ", "))
	expectCount("Config has exactly two email-shaped fields", len(emailish), 2)
	expectString("both are interfaces and nothing else",
		strings.Join(emailish, ", "), "EmailSender interface, MagicLinkSender interface")
	senderType := reflect.TypeOf((*notify.EmailSender)(nil)).Elem()
	linkType := reflect.TypeOf((*notify.MagicLinkSender)(nil)).Elem()
	expectTrue("one method each", senderType.NumMethod() == 1 && linkType.NumMethod() == 1)
	expectString("EmailSender takes a recipient and a token",
		senderType.Method(0).Type.String(), "func(context.Context, string, string) error")
	expectString("MagicLinkSender takes a recipient and a token",
		linkType.Method(0).Type.String(), "func(context.Context, string, string) error")

	section("A provider failure is the host's error, and nothing half-happens")
	h3 := newHarness("smtp-shaped")
	h3.mailer.failWith = errors.New("provider rejected the message")
	thirdID := userIDFor(ctx, h3, email)
	err = cryden.RequestEmailChange(ctx, h3.engine, thirdID, newEmail)
	expectTrue("the send error reached the caller unchanged",
		err != nil && strings.Contains(err.Error(), "provider rejected the message"))
	expectCount("nothing was recorded as sent", h3.mailer.count(), 0)
	_, err = cryden.GetUser(ctx, h3.engine, newEmail)
	expectErrorIs("the address did not change", err, store.ErrNotFound)
	_, err = cryden.GetUser(ctx, h3.engine, email)
	check("the account still answers to its old address", err)

	section("An unknown address sends nothing at all")
	h3.mailer.reset()
	// Enumeration-avoidance: RequestMagicLink returns nil for an address
	// with no account. A host's "check your inbox" page is therefore a
	// promise the engine has not made — worth knowing before writing it.
	check("a magic link for an unknown address returns no error",
		cryden.RequestMagicLink(ctx, h3.engine, "nobody@acme.example", "1.2.3.4"))
	expectCount("and the mailer was never called", h3.mailer.count(), 0)

	section("What the engine does not tell the sender")
	check("magic link requested", cryden.RequestMagicLink(ctx, h3.engine, email, "1.2.3.4"))
	loginMail := h3.mailer.last()
	// The host owns the VerificationStore, so this is where an expiry is
	// discoverable — it is not a parameter of either send method.
	vt, err := h3.verifications.GetByTokenHash(ctx, token.HashToken(loginMail.token))
	check("the stored token found by its hash", err)
	loginTTL := time.Until(vt.ExpiresAt)
	expectTrue("a login link really lasts 15 minutes",
		loginTTL > 14*time.Minute && loginTTL <= 15*time.Minute)
	expectString("which is what the host's template hardcodes", loginMail.expires, loginExpires)
	check("email change requested", cryden.RequestEmailChange(ctx, h3.engine, thirdID, newEmail))
	verifyMail := h3.mailer.last()
	vt2, err := h3.verifications.GetByTokenHash(ctx, token.HashToken(verifyMail.token))
	check("the stored change token found by its hash", err)
	verifyTTL := time.Until(vt2.ExpiresAt)
	expectTrue("a confirmation link really lasts 1 hour",
		verifyTTL > 59*time.Minute && verifyTTL <= 60*time.Minute)
	expectString("which is also what the template hardcodes", verifyMail.expires, verifyExpires)
	expectTrue("the sender itself was told neither the expiry nor the user ID",
		!strings.Contains(verifyMail.body+verifyMail.subject, vt2.UserID))

	section("What is actually sent")
	for _, d := range []delivery{verifyMail, loginMail, german} {
		fmt.Printf("  [%s/%s] to %s via %s\n  subject: %s\n", d.kind, d.locale, d.to, d.provider, d.subject)
		for _, line := range strings.Split(d.body, "\n") {
			fmt.Printf("  | %s\n", line)
		}
	}
	expectTrue("no email anywhere contains the password",
		!anyContains(password, h.mailer, h2.mailer, h3.mailer))
	expectTrue("every email carries the token it was sent to deliver",
		everyDeliveryCarriesItsToken(h.mailer, h2.mailer, h3.mailer))

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
		return
	}
	fmt.Printf("%d CHECK(S) FAILED\n", failures)
	os.Exit(1)
}

func userIDFor(ctx context.Context, h *harness, address string) string {
	u, err := cryden.GetUser(ctx, h.engine, address)
	if err != nil {
		fail("user lookup for " + address + ": " + err.Error())
		return ""
	}
	return u.ID
}

// linkToken pulls the token back out of the host's own composed HTML —
// the same thing a user's browser does when they click the link.
func linkToken(body string) (string, error) {
	const marker = `href="`
	i := strings.Index(body, marker)
	if i < 0 {
		return "", errors.New("no href in the composed email")
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return "", errors.New("unterminated href in the composed email")
	}
	u, err := url.Parse(html.UnescapeString(rest[:j]))
	if err != nil {
		return "", err
	}
	raw := u.Query().Get("token")
	if raw == "" {
		return "", errors.New("no token parameter in the link")
	}
	return raw, nil
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return s != ""
}

func anyContains(needle string, mailers ...*acmeMailer) bool {
	for _, m := range mailers {
		for _, d := range m.sent {
			if strings.Contains(d.subject+d.body, needle) {
				return true
			}
		}
	}
	return false
}

func everyDeliveryCarriesItsToken(mailers ...*acmeMailer) bool {
	for _, m := range mailers {
		for _, d := range m.sent {
			if !strings.Contains(d.body, d.token) {
				return false
			}
		}
	}
	return true
}

func section(name string) {
	fmt.Printf("\n— %s\n", name)
}

func check(step string, err error) {
	if err != nil {
		fail(fmt.Sprintf("%s: unexpected error: %v", step, err))
		return
	}
	pass(step)
}

func expectErrorIs(step string, got, want error) {
	if !errors.Is(got, want) {
		fail(fmt.Sprintf("%s: got %v, want %v", step, got, want))
		return
	}
	pass(fmt.Sprintf("%s → %v", step, want))
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

func expectTrue(step string, ok bool) {
	if !ok {
		fail(step)
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
