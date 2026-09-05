package cryden

import (
	"context"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/crydensync/cryden/v2/notify"
	"github.com/crydensync/cryden/v2/store/memory"
)

// These tests pin a verdict rather than a feature: email templates are
// already entirely the host app's, because the engine composes nothing
// and offers nowhere to configure a template. That stays true only if
// nobody later adds a subject, a body, a from-address or a template
// field to Config — which is what the reflection below is for. It fails
// on the commit that adds one, in `go test ./...`, instead of quietly
// making the manual guide wrong.

// The two send methods are the engine's entire outward email surface.
// Both take a recipient and a raw token; neither has anywhere to put a
// subject, a body, a URL or a locale.
func TestEmailInterfaces_TakeOnlyARecipientAndAToken(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  reflect.Type
	}{
		{"notify.EmailSender", reflect.TypeOf((*notify.EmailSender)(nil)).Elem()},
		{"notify.MagicLinkSender", reflect.TypeOf((*notify.MagicLinkSender)(nil)).Elem()},
	} {
		if got := tc.typ.NumMethod(); got != 1 {
			t.Errorf("%s has %d methods, want 1", tc.name, got)
			continue
		}
		const want = "func(context.Context, string, string) error"
		if got := tc.typ.Method(0).Type.String(); got != want {
			t.Errorf("%s.%s is %s, want %s", tc.name, tc.typ.Method(0).Name, got, want)
		}
	}
}

// Config's only email-shaped fields are the two senders, and both are
// interfaces the host implements. A new field named anything like
// EmailSubject, EmailTemplate, FromAddress or SMTPHost fails this.
func TestConfig_HasNoEmailTemplateKnobs(t *testing.T) {
	var found []string
	cfgType := reflect.TypeOf(Config{})
	for i := 0; i < cfgType.NumField(); i++ {
		f := cfgType.Field(i)
		lower := strings.ToLower(f.Name)
		for _, needle := range []string{"email", "mail", "sender", "template", "subject", "body", "smtp", "html", "from"} {
			if strings.Contains(lower, needle) {
				found = append(found, f.Name+" "+f.Type.Kind().String())
				break
			}
		}
	}
	want := []string{"EmailSender interface", "MagicLinkSender interface"}
	if !reflect.DeepEqual(found, want) {
		t.Errorf("Config's email-shaped fields are %v, want exactly %v", found, want)
	}
}

// composingSender is a host app's mailer: it receives two strings and
// writes the whole email itself, including the URL and the domain.
type composingSender struct {
	subject, body, to string
	calls             int
}

func (s *composingSender) SendVerification(_ context.Context, to, rawToken string) error {
	s.calls++
	s.to = to
	s.subject = "Confirm your new address"
	s.body = `<a href="https://host.example/confirm?token=` + url.QueryEscape(rawToken) + `">Confirm</a>`
	return nil
}

var _ notify.EmailSender = (*composingSender)(nil)

// The round trip that makes the verdict real: a link the host composed,
// on the host's own domain, in the host's own markup, is accepted by
// the engine — so owning the template costs the host nothing.
func TestRequestEmailChange_AcceptsALinkTheHostComposed(t *testing.T) {
	sender := &composingSender{}
	cfg := validConfig()
	cfg.Verifications = memory.NewVerificationStore()
	cfg.EmailSender = sender
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx := context.Background()

	user, err := SignUp(ctx, e, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if err := RequestEmailChange(ctx, e, user.ID, "ray@acme.example"); err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	if sender.calls != 1 || sender.to != "ray@acme.example" {
		t.Fatalf("sender got %d call(s) for %q, want 1 for the new address", sender.calls, sender.to)
	}

	// Pull the token back out of the host's own HTML, exactly as the
	// user's browser would.
	href := sender.body[strings.Index(sender.body, `"`)+1:]
	link, err := url.Parse(href[:strings.Index(href, `"`)])
	if err != nil {
		t.Fatalf("the host's own link did not parse: %v", err)
	}
	raw := link.Query().Get("token")
	if raw == "" {
		t.Fatal("no token in the host's link")
	}

	if err := ConfirmEmailChange(ctx, e, raw); err != nil {
		t.Fatalf("ConfirmEmailChange with the host-composed link: %v", err)
	}
	moved, err := GetUser(ctx, e, "ray@acme.example")
	if err != nil {
		t.Fatalf("the account did not move: %v", err)
	}
	if moved.ID != user.ID {
		t.Errorf("moved account is %q, want %q", moved.ID, user.ID)
	}
}
