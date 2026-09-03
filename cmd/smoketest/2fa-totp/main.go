// Command 2fa-totp is a standalone, no-database smoke test for the
// full TOTP (2FA) flow: enroll, confirm, login-pauses, complete, and
// the negative cases (wrong code, tampered pending token, a real
// access token used where a pending token is expected). Run with:
//
//	go run ./cmd/smoketest/2fa-totp
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

func main() {
	ctx := context.Background()

	engine, err := cryden.New(cryden.Config{
		JWTSecret:      "smoketest-jwt-secret",
		Users:          memory.NewUserStore(),
		Sessions:       memory.NewSessionStore(),
		Audit:          memory.NewAuditStore(),
		TOTP:           memory.NewTOTPStore(),
		EncryptionKey:  "smoketest-encryption-key", // deliberately different from JWTSecret
		TOTPIssuerName: "CrydenSync Smoke Test",
	})
	check("engine constructed", err)

	user, err := cryden.SignUp(ctx, engine, email, password, "1.2.3.4")
	check("signed up", err)

	// 1. Login before TOTP is enrolled — must succeed directly.
	_, err = cryden.Login(ctx, engine, email, password, "1.2.3.4", "smoketest-agent")
	check("login before enrollment issues tokens directly", err)

	// 2. Enroll TOTP.
	otpauthURL, err := cryden.EnrollTOTP(ctx, engine, user.ID)
	check("enrolled TOTP", err)

	secret, err := extractSecretFromURL(otpauthURL)
	check("extracted secret from otpauth URL", err)

	// 3. Login before confirming — must still succeed directly. An
	// unconfirmed secret must never gate login.
	_, err = cryden.Login(ctx, engine, email, password, "1.2.3.4", "smoketest-agent")
	check("login with UNCONFIRMED TOTP still issues tokens directly", err)

	// 4. Confirming with a wrong code must fail, and must not confirm.
	err = cryden.ConfirmTOTP(ctx, engine, user.ID, "000000")
	checkExpectError("confirm with wrong code is rejected", err)

	_, err = cryden.Login(ctx, engine, email, password, "1.2.3.4", "smoketest-agent")
	check("login still issues tokens directly after a failed confirm attempt", err)

	// 5. Confirm with a real code.
	code, err := totp.GenerateCode(secret, time.Now())
	check("generated a real code", err)
	err = cryden.ConfirmTOTP(ctx, engine, user.ID, code)
	check("confirmed TOTP enrollment", err)

	// 6. Login now — must pause with *auth.ErrTOTPRequired, no tokens.
	pendingToken1 := requirePending(ctx, engine, "login after confirmation returns *auth.ErrTOTPRequired")

	// 7. Complete with a wrong code — must be rejected.
	_, err = cryden.CompleteLoginWithTOTP(ctx, engine, pendingToken1, "000000", "1.2.3.4", "smoketest-agent")
	checkExpectError("complete login with wrong code is rejected", err)

	// 8. Complete with a tampered/garbage pending token — must be rejected.
	code, _ = totp.GenerateCode(secret, time.Now())
	_, err = cryden.CompleteLoginWithTOTP(ctx, engine, "not-a-real-pending-token", code, "1.2.3.4", "smoketest-agent")
	checkExpectError("complete login with a garbage pending token is rejected", err)

	// 9. Correct code completes login successfully.
	code, _ = totp.GenerateCode(secret, time.Now())
	realTokens, err := cryden.CompleteLoginWithTOTP(ctx, engine, pendingToken1, code, "1.2.3.4", "smoketest-agent")
	check("completed login with a correct code", err)
	if realTokens.AccessToken == "" || realTokens.RefreshToken == "" {
		fail("expected both tokens to be populated after successful completion")
	} else {
		pass("both tokens populated after successful completion")
	}

	// 10. Use that REAL access token where a pending token is
	// expected — must be rejected. Both are signed with the same
	// secret; this specifically checks the "typ" claim guarding
	// against confusion between the two token types.
	pendingToken2 := requirePending(ctx, engine, "login still requires 2FA on the next attempt")
	code, _ = totp.GenerateCode(secret, time.Now())
	_, err = cryden.CompleteLoginWithTOTP(ctx, engine, realTokens.AccessToken, code, "1.2.3.4", "smoketest-agent")
	checkExpectError("using a real access token as a pending token is rejected", err)

	// Clean up that still-pending login before moving on.
	code, _ = totp.GenerateCode(secret, time.Now())
	_, err = cryden.CompleteLoginWithTOTP(ctx, engine, pendingToken2, code, "1.2.3.4", "smoketest-agent")
	check("completed the pending login from step 10", err)

	// 11. Disable TOTP with the wrong password — must be rejected, secret stays.
	err = cryden.DisableTOTP(ctx, engine, user.ID, "wrong-password")
	checkExpectError("disable TOTP with wrong password is rejected", err)

	// 12. Disable TOTP with the correct password — login goes back to direct.
	err = cryden.DisableTOTP(ctx, engine, user.ID, password)
	check("disabled TOTP with correct password", err)

	_, err = cryden.Login(ctx, engine, email, password, "1.2.3.4", "smoketest-agent")
	check("login after disabling TOTP issues tokens directly again", err)

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
	} else {
		fmt.Printf("%d CHECK(S) FAILED\n", failures)
		os.Exit(1)
	}
}

// requirePending logs in and asserts the account is correctly paused
// on *auth.ErrTOTPRequired, returning the pending token for the
// caller to complete or probe against.
func requirePending(ctx context.Context, engine *cryden.Engine, step string) string {
	tokens, err := cryden.Login(ctx, engine, email, password, "1.2.3.4", "smoketest-agent")
	var totpRequired *auth.ErrTOTPRequired
	if !errors.As(err, &totpRequired) {
		fail(fmt.Sprintf("%s: expected *auth.ErrTOTPRequired, got %v", step, err))
		return ""
	}
	if tokens.AccessToken != "" {
		fail(fmt.Sprintf("%s: expected no access token to be issued", step))
	}
	if totpRequired.PendingToken == "" {
		fail(fmt.Sprintf("%s: expected a non-empty pending token", step))
	}
	pass(step)
	return totpRequired.PendingToken
}

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

func check(step string, err error) {
	if err != nil {
		fail(fmt.Sprintf("%s: unexpected error: %v", step, err))
		return
	}
	pass(step)
}

// checkExpectError is used for the negative cases — a nil error here
// is the failure.
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
