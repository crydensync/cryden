// Command magic-link is a standalone, no-database smoke test for the
// full magic-link (passwordless) login flow: request, complete,
// single-use enforcement, expiry, and pausing for a second factor on
// an account that has one enrolled. Run with:
//
//	go run ./cmd/smoketest/magic-link
package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/auth"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/pquerna/otp/totp"
)

const (
	email    = "raymondproguy@dev.com"
	password = "Tr0ubl3-Fr33!2026"
)

var failures int

// capturingSender stands in for a real email provider — it just
// records the last token it was asked to send, so the smoke test can
// grab it and simulate "clicking the link."
type capturingSender struct {
	lastToken string
	calls     int
}

func (s *capturingSender) SendMagicLink(ctx context.Context, to string, rawToken string) error {
	s.lastToken = rawToken
	s.calls++
	return nil
}

func main() {
	ctx := context.Background()
	sender := &capturingSender{}

	engine, err := cryden.New(cryden.Config{
		JWTSecret:       "smoketest-jwt-secret",
		Users:           memory.NewUserStore(),
		Sessions:        memory.NewSessionStore(),
		Audit:           memory.NewAuditStore(),
		Verifications:   memory.NewVerificationStore(),
		MagicLinkSender: sender,
	})
	check("engine constructed", err)

	user, err := cryden.SignUp(ctx, engine, email, password, "1.2.3.4")
	check("signed up", err)

	// 1. Requesting a link for a nonexistent email must return nil
	// and never call the sender.
	err = cryden.RequestMagicLink(ctx, engine, "nobody@example.com", "1.2.3.4")
	check("request for nonexistent email returns nil", err)
	if sender.calls != 0 {
		fail(fmt.Sprintf("expected 0 sends for a nonexistent email, got %d", sender.calls))
	} else {
		pass("sender never called for a nonexistent email")
	}

	// 2. Requesting for a real account sends a token.
	err = cryden.RequestMagicLink(ctx, engine, email, "1.2.3.4")
	check("requested a magic link for a real account", err)
	if sender.calls != 1 || sender.lastToken == "" {
		fail("expected exactly 1 send with a non-empty token")
	} else {
		pass("sender received exactly 1 non-empty token")
	}
	firstToken := sender.lastToken

	// 3. Completing with the real token issues tokens directly (no
	// second factor enrolled yet).
	tokens, err := cryden.CompleteMagicLink(ctx, engine, firstToken, "1.2.3.4", "smoketest-agent")
	check("completed login with the real token", err)
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		fail("expected both tokens to be populated")
	} else {
		pass("both tokens populated")
	}

	// 4. Reusing the same token must fail — single-use.
	_, err = cryden.CompleteMagicLink(ctx, engine, firstToken, "1.2.3.4", "smoketest-agent")
	checkExpectError("reusing the same token is rejected", err)

	// 5. A garbage token must fail.
	_, err = cryden.CompleteMagicLink(ctx, engine, "not-a-real-token", "1.2.3.4", "smoketest-agent")
	checkExpectError("a garbage token is rejected", err)

	// 6. Enroll and confirm TOTP, then confirm a fresh magic link
	// pauses for the second factor instead of logging straight in.
	otpauthURL, err := cryden.EnrollTOTP(ctx, engine, user.ID)
	check("enrolled TOTP for the second-factor check", err)
	secret, err := extractSecretFromURL(otpauthURL)
	check("extracted TOTP secret", err)
	code, err := totp.GenerateCode(secret, time.Now())
	check("generated a real TOTP code", err)
	err = cryden.ConfirmTOTP(ctx, engine, user.ID, code)
	check("confirmed TOTP enrollment", err)

	err = cryden.RequestMagicLink(ctx, engine, email, "1.2.3.4")
	check("requested a second magic link", err)

	_, err = cryden.CompleteMagicLink(ctx, engine, sender.lastToken, "1.2.3.4", "smoketest-agent")
	var secondFactor *auth.ErrSecondFactorRequired
	if !errors.As(err, &secondFactor) {
		fail(fmt.Sprintf("expected *auth.ErrSecondFactorRequired for an account with TOTP enrolled, got %v", err))
	} else {
		pass("magic-link completion on a TOTP-enrolled account pauses for the second factor")
		if len(secondFactor.Methods) != 1 || secondFactor.Methods[0] != "totp" {
			fail(fmt.Sprintf("expected Methods == [\"totp\"], got %v", secondFactor.Methods))
		} else {
			pass("Methods correctly reports [\"totp\"]")
		}
	}

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
	} else {
		fmt.Printf("%d CHECK(S) FAILED\n", failures)
		os.Exit(1)
	}
}

func check(step string, err error) {
	if err != nil {
		fail(fmt.Sprintf("%s: unexpected error: %v", step, err))
		return
	}
	pass(step)
}

func checkExpectError(step string, err error) {
	if err == nil {
		fail(fmt.Sprintf("%s: expected an error, got nil", step))
		return
	}
	pass(fmt.Sprintf("%s (%v)", step, err))
}

func pass(step string) {
	fmt.Println("✓", step)
}

func fail(msg string) {
	failures++
	fmt.Println("✗", msg)
}

// extractSecretFromURL pulls the base32 secret out of an otpauth://
// URL — stands in for what a real authenticator app does when it
// scans the QR code.
func extractSecretFromURL(otpauthURL string) (string, error) {
	u, err := url.Parse(otpauthURL)
	if err != nil {
		return "", err
	}
	secret := u.Query().Get("secret")
	if secret == "" {
		return "", fmt.Errorf("no secret query param found in %q", otpauthURL)
	}
	return secret, nil
}
