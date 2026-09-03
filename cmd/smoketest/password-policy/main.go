// Command password-policy is a standalone, no-database smoke test for
// password policy enforcement: the default policy applying
// automatically when unset, rejecting short/over-length passwords,
// reporting multiple violations together, and a custom stricter
// policy. Run with:
//
//	go run ./cmd/smoketest/password-policy
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/auth"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store/memory"
)

var failures int

func main() {
	ctx := context.Background()

	// 1. Leaving PasswordPolicy unset applies the default (min 8).
	defaultEngine, err := cryden.New(cryden.Config{
		JWTSecret: "smoketest-jwt-secret",
		Users:     memory.NewUserStore(),
		Sessions:  memory.NewSessionStore(),
		Audit:     memory.NewAuditStore(),
	})
	check("default engine constructed", err)

	_, err = cryden.SignUp(ctx, defaultEngine, "raymondproguy@dev.com", "short1", "1.2.3.4")
	checkExpectError("a 6-character password is rejected under the default policy (min 8)", err)

	_, err = cryden.SignUp(ctx, defaultEngine, "raymondproguy@dev.com", "eightplus", "1.2.3.4")
	check("a 9-character password satisfies the default policy", err)

	// 2. Over 72 bytes is rejected — bcrypt's real limit.
	longPassword := make([]byte, 73)
	for i := range longPassword {
		longPassword[i] = 'a'
	}
	_, err = cryden.SignUp(ctx, defaultEngine, "raymondproguy2@dev.com", string(longPassword), "1.2.3.4")
	checkExpectError("a 73-byte password is rejected under the default policy (max 72)", err)

	// 3. A custom stricter policy reports multiple violations together.
	strictEngine, err := cryden.New(cryden.Config{
		JWTSecret: "smoketest-jwt-secret-2",
		Users:     memory.NewUserStore(),
		Sessions:  memory.NewSessionStore(),
		Audit:     memory.NewAuditStore(),
		PasswordPolicy: security.PasswordPolicy{
			MinLength:        12,
			RequireUppercase: true,
			RequireDigit:     true,
		},
	})
	check("strict engine constructed", err)

	_, err = cryden.SignUp(ctx, strictEngine, "raymondproguy@dev.com", "lowercase", "1.2.3.4")
	var violation *auth.ErrPasswordPolicyViolation
	if !errors.As(err, &violation) {
		fail(fmt.Sprintf("expected *auth.ErrPasswordPolicyViolation, got %v", err))
	} else {
		pass("a password missing multiple requirements is rejected")
		hasMinLength, hasUppercase, hasDigit := false, false, false
		for _, v := range violation.Violations {
			switch v {
			case "min_length":
				hasMinLength = true
			case "require_uppercase":
				hasUppercase = true
			case "require_digit":
				hasDigit = true
			}
		}
		if hasMinLength && hasUppercase && hasDigit {
			pass("all three violations (min_length, require_uppercase, require_digit) reported together")
		} else {
			fail(fmt.Sprintf("expected all three violations reported together, got %v", violation.Violations))
		}
	}

	// 4. A password satisfying the custom policy succeeds.
	_, err = cryden.SignUp(ctx, strictEngine, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4")
	check("a password satisfying the custom policy succeeds", err)

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
