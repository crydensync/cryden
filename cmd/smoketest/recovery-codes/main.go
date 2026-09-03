// Command recovery-codes is a standalone, no-database smoke test for
// the recovery (backup) code flow: generation, login completion,
// single-use enforcement, regeneration invalidating the previous
// batch, and — the important safety property — leftover codes never
// gating login once the real second factor is gone. Run with:
//
//	go run ./cmd/smoketest/recovery-codes
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
		RecoveryCodes:  memory.NewRecoveryCodeStore(),
		EncryptionKey:  "smoketest-encryption-key",
		TOTPIssuerName: "CrydenSync Smoke Test",
	})
	check("engine constructed", err)

	user, err := cryden.SignUp(ctx, engine, email, password, "1.2.3.4")
	check("signed up", err)

	// 1. Generating codes before any second factor exists must fail.
	_, err = cryden.GenerateRecoveryCodes(ctx, engine, user.ID)
	checkExpectError("generating codes with no second factor enrolled is rejected", err)

	// 2. Enroll and confirm TOTP.
	otpauthURL, err := cryden.EnrollTOTP(ctx, engine, user.ID)
	check("enrolled TOTP", err)
	secret, err := extractSecretFromURL(otpauthURL)
	check("extracted TOTP secret", err)
	code, err := totp.GenerateCode(secret, time.Now())
	check("generated a real TOTP code", err)
	err = cryden.ConfirmTOTP(ctx, engine, user.ID, code)
	check("confirmed TOTP enrollment", err)

	// 3. Generate a real batch of codes.
	firstBatch, err := cryden.GenerateRecoveryCodes(ctx, engine, user.ID)
	check("generated a batch of recovery codes", err)
	if len(firstBatch) != 10 {
		fail(fmt.Sprintf("expected 10 codes, got %d", len(firstBatch)))
	} else {
		pass("received exactly 10 codes")
	}

	// 4. Login now pauses, reporting both totp and recovery_code as
	// available methods.
	pendingToken1, methods := requireSecondFactor(ctx, engine, "login after TOTP confirmation returns *auth.ErrSecondFactorRequired")
	hasTOTP, hasRecovery := false, false
	for _, m := range methods {
		if m == "totp" {
			hasTOTP = true
		}
		if m == "recovery_code" {
			hasRecovery = true
		}
	}
	if !hasTOTP || !hasRecovery {
		fail(fmt.Sprintf("expected Methods to contain both totp and recovery_code, got %v", methods))
	} else {
		pass("Methods correctly reports both totp and recovery_code")
	}

	// 5. Complete login with a real recovery code.
	realTokens, err := cryden.CompleteLoginWithRecoveryCode(ctx, engine, pendingToken1, firstBatch[0], "1.2.3.4", "smoketest-agent")
	check("completed login with a real recovery code", err)
	if realTokens.AccessToken == "" || realTokens.RefreshToken == "" {
		fail("expected both tokens to be populated")
	} else {
		pass("both tokens populated")
	}

	// 6. The same code must not work twice.
	pendingToken2, _ := requireSecondFactor(ctx, engine, "login again requires a second factor")
	_, err = cryden.CompleteLoginWithRecoveryCode(ctx, engine, pendingToken2, firstBatch[0], "1.2.3.4", "smoketest-agent")
	checkExpectError("reusing the same recovery code is rejected", err)

	// 7. A wrong code must be rejected.
	_, err = cryden.CompleteLoginWithRecoveryCode(ctx, engine, pendingToken2, "wrong-code", "1.2.3.4", "smoketest-agent")
	checkExpectError("a wrong recovery code is rejected", err)

	// Clean up that still-pending login with a fresh unused code before continuing.
	_, err = cryden.CompleteLoginWithRecoveryCode(ctx, engine, pendingToken2, firstBatch[1], "1.2.3.4", "smoketest-agent")
	check("completed the pending login from step 6/7 with a fresh code", err)

	// 8. Regenerate — the old batch must be fully invalidated.
	secondBatch, err := cryden.GenerateRecoveryCodes(ctx, engine, user.ID)
	check("regenerated recovery codes", err)
	pendingToken3, _ := requireSecondFactor(ctx, engine, "login requires a second factor before testing regeneration")
	_, err = cryden.CompleteLoginWithRecoveryCode(ctx, engine, pendingToken3, firstBatch[2], "1.2.3.4", "smoketest-agent")
	checkExpectError("a code from the invalidated first batch is rejected after regeneration", err)
	_, err = cryden.CompleteLoginWithRecoveryCode(ctx, engine, pendingToken3, secondBatch[0], "1.2.3.4", "smoketest-agent")
	check("a code from the new batch still works", err)

	// 9. Disable TOTP (the account's only real second factor) and
	// confirm any leftover recovery codes stop gating login entirely
	// — this is the property that actually matters.
	err = cryden.DisableTOTP(ctx, engine, user.ID, password)
	check("disabled TOTP", err)

	_, err = cryden.Login(ctx, engine, email, password, "1.2.3.4", "smoketest-agent")
	check("login after disabling TOTP issues tokens directly — leftover recovery codes did not become a standalone backdoor", err)

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
	} else {
		fmt.Printf("%d CHECK(S) FAILED\n", failures)
		os.Exit(1)
	}
}

// requireSecondFactor logs in and asserts the account is correctly
// paused on *auth.ErrSecondFactorRequired, returning the pending
// token and enrolled methods. Returns "" and nil on failure rather
// than panicking, so one bad assertion doesn't crash the rest of the
// smoke test.
func requireSecondFactor(ctx context.Context, engine *cryden.Engine, step string) (string, []string) {
	_, err := cryden.Login(ctx, engine, email, password, "1.2.3.4", "smoketest-agent")
	var secondFactor *auth.ErrSecondFactorRequired
	if !errors.As(err, &secondFactor) {
		fail(fmt.Sprintf("%s: expected *auth.ErrSecondFactorRequired, got %v", step, err))
		return "", nil
	}
	pass(step)
	return secondFactor.PendingToken, secondFactor.Methods
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
