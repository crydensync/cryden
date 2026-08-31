// Command webauthn-passkeys is a standalone, no-database smoke test
// for the full passkey (WebAuthn second-factor) flow: register,
// login-pauses, complete via a real simulated authenticator, and the
// negative cases (garbage response, tampered ceremony token, a real
// access token used where a pending token is expected, no passkeys
// enrolled). Uses github.com/descope/virtualwebauthn to stand in for
// a real browser + authenticator — the only way to exercise the
// actual cryptographic verification success path, not just the
// rejection path a hand-built fake response would be limited to.
//
// Run with:
//
//	go run ./cmd/smoketest/webauthn-passkeys
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/descope/virtualwebauthn"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/auth"
	"github.com/crydensync/cryden/v2/store/memory"
)

const (
	email    = "raymondproguy@dev.com"
	password = "Tr0ubl3-Fr33!2026"

	rpDisplayName = "CrydenSync Smoke Test"
	rpID          = "example.com"
	rpOrigin      = "https://example.com"
)

var failures int

func main() {
	ctx := context.Background()

	engine, err := cryden.New(cryden.Config{
		JWTSecret:             "smoketest-jwt-secret",
		Users:                 memory.NewUserStore(),
		Sessions:              memory.NewSessionStore(),
		Audit:                 memory.NewAuditStore(),
		WebAuthn:              memory.NewWebAuthnStore(),
		EncryptionKey:         "smoketest-encryption-key",
		WebAuthnRPID:          rpID,
		WebAuthnRPDisplayName: rpDisplayName,
		WebAuthnRPOrigins:     []string{rpOrigin},
	})
	check("engine constructed", err)

	user, err := cryden.SignUp(ctx, engine, email, password, "1.2.3.4")
	check("signed up", err)

	// 1. Login before any passkey is registered — must succeed directly.
	_, err = cryden.Login(ctx, engine, email, password, "1.2.3.4", "smoketest-agent")
	check("login before registration issues tokens directly", err)

	// 2. Begin registering a passkey.
	creationJSON, ceremonyToken, err := cryden.BeginRegisterPasskey(ctx, engine, user.ID)
	check("began passkey registration", err)

	// Simulate a real browser + authenticator producing a valid response.
	rp := virtualwebauthn.RelyingParty{Name: rpDisplayName, ID: rpID, Origin: rpOrigin}
	authenticator := virtualwebauthn.NewAuthenticator()
	vCred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(creationJSON))
	check("parsed attestation options", err)
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, vCred, *attestationOptions)

	// 3. A garbage response must be rejected, and must not register anything.
	err = cryden.FinishRegisterPasskey(ctx, engine, user.ID, ceremonyToken, []byte(`{"not":"real"}`), "")
	checkExpectError("garbage registration response is rejected", err)

	// 4. Finish registration with the real response.
	err = cryden.FinishRegisterPasskey(ctx, engine, user.ID, ceremonyToken, []byte(attestationResponse), "Smoke Test Device")
	check("finished passkey registration with a real response", err)

	authenticator.AddCredential(vCred)
	authenticator.Options.UserHandle = []byte(user.ID)

	// 5. List passkeys — should show exactly one, with the nickname.
	passkeys, err := cryden.ListPasskeys(ctx, engine, user.ID)
	check("listed passkeys", err)
	if len(passkeys) != 1 {
		fail(fmt.Sprintf("expected 1 registered passkey, got %d", len(passkeys)))
	} else if passkeys[0].Nickname != "Smoke Test Device" {
		fail(fmt.Sprintf("expected nickname 'Smoke Test Device', got %q", passkeys[0].Nickname))
	} else {
		pass("exactly one passkey listed, with the correct nickname")
	}

	// 6. Login now — must pause with *auth.ErrSecondFactorRequired,
	// reporting "webauthn" as an available method.
	pendingToken1, methods := requireSecondFactor(ctx, engine, "login after registration returns *auth.ErrSecondFactorRequired")
	if len(methods) != 1 || methods[0] != "webauthn" {
		fail(fmt.Sprintf("expected Methods == [\"webauthn\"], got %v", methods))
	} else {
		pass("Methods correctly reports [\"webauthn\"]")
	}

	// 7. Begin the login ceremony.
	assertionJSON, loginCeremonyToken, err := cryden.BeginWebAuthnLogin(ctx, engine, pendingToken1)
	check("began webauthn login", err)

	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(assertionJSON))
	check("parsed assertion options", err)
	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, vCred, *assertionOptions)

	// 8. Garbage login response must be rejected.
	_, err = cryden.CompleteLoginWithWebAuthn(ctx, engine, pendingToken1, loginCeremonyToken, []byte(`{"not":"real"}`), "1.2.3.4", "smoketest-agent")
	checkExpectError("garbage login response is rejected", err)

	// 9. Tampered/garbage ceremony token must be rejected.
	_, err = cryden.CompleteLoginWithWebAuthn(ctx, engine, pendingToken1, "not-a-real-ceremony-token", []byte(assertionResponse), "1.2.3.4", "smoketest-agent")
	checkExpectError("tampered ceremony token is rejected", err)

	// 10. Correct response completes login successfully.
	realTokens, err := cryden.CompleteLoginWithWebAuthn(ctx, engine, pendingToken1, loginCeremonyToken, []byte(assertionResponse), "1.2.3.4", "smoketest-agent")
	check("completed login with a correct passkey response", err)
	if realTokens.AccessToken == "" || realTokens.RefreshToken == "" {
		fail("expected both tokens to be populated after successful completion")
	} else {
		pass("both tokens populated after successful completion")
	}

	// 11. A real access token must never work as a pending token —
	// specifically checks the "typ" claim guarding against confusion
	// between the two token types.
	pendingToken2, _ := requireSecondFactor(ctx, engine, "login again requires webauthn")
	assertionJSON2, ceremonyToken2, err := cryden.BeginWebAuthnLogin(ctx, engine, pendingToken2)
	check("began a second webauthn login", err)
	assertionOptions2, err := virtualwebauthn.ParseAssertionOptions(string(assertionJSON2))
	check("parsed second assertion options", err)
	assertionResponse2 := virtualwebauthn.CreateAssertionResponse(rp, authenticator, vCred, *assertionOptions2)

	_, err = cryden.CompleteLoginWithWebAuthn(ctx, engine, realTokens.AccessToken, ceremonyToken2, []byte(assertionResponse2), "1.2.3.4", "smoketest-agent")
	checkExpectError("using a real access token as a pending token is rejected", err)

	// Clean up that still-pending login before moving on.
	_, err = cryden.CompleteLoginWithWebAuthn(ctx, engine, pendingToken2, ceremonyToken2, []byte(assertionResponse2), "1.2.3.4", "smoketest-agent")
	check("completed the pending login from step 11", err)

	// 12. Delete the passkey — wrong password first, must be rejected.
	err = cryden.DeletePasskey(ctx, engine, user.ID, passkeys[0].CredentialID, "wrong-password")
	checkExpectError("delete passkey with wrong password is rejected", err)

	// 13. Delete with the correct password — login goes back to direct.
	err = cryden.DeletePasskey(ctx, engine, user.ID, passkeys[0].CredentialID, password)
	check("deleted passkey with correct password", err)

	_, err = cryden.Login(ctx, engine, email, password, "1.2.3.4", "smoketest-agent")
	check("login after deleting the passkey issues tokens directly again", err)

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

// requireSecondFactor logs in and asserts the account is correctly
// paused on *auth.ErrSecondFactorRequired, returning the pending
// token and enrolled methods for the caller to act on. Returns ""
// and nil on failure rather than panicking, so one bad assertion
// doesn't crash the rest of the smoke test.
func requireSecondFactor(ctx context.Context, engine *cryden.Engine, step string) (pendingToken string, methods []string) {
	_, err := cryden.Login(ctx, engine, email, password, "1.2.3.4", "smoketest-agent")
	var secondFactor *auth.ErrSecondFactorRequired
	if !errors.As(err, &secondFactor) {
		fail(fmt.Sprintf("%s: expected *auth.ErrSecondFactorRequired, got %v", step, err))
		return "", nil
	}
	pass(step)
	return secondFactor.PendingToken, secondFactor.Methods
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
