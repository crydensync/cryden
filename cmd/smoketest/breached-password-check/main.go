// Command breached-password-check is a standalone, no-database smoke
// test for the breach-checking flow: a confirmed breach rejects the
// password, and a checker error fails open. Uses two tiny local fake
// checkers, not a real HIBP client — see
// docs/testing/breached-password-check.md for why, and how to verify
// against the real API instead. Run with:
//
//	go run ./cmd/smoketest/breached-password-check
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store/memory"
)

var failures int

// fakeChecker is a controllable stand-in for a real breach-checking
// service — reports a fixed result or a fixed error, and records how
// many times it was called.
type fakeChecker struct {
	breached bool
	err      error
	calls    int
}

func (f *fakeChecker) IsBreached(ctx context.Context, password string) (bool, error) {
	f.calls++
	return f.breached, f.err
}

func main() {
	ctx := context.Background()

	// 1. A confirmed breach rejects the password.
	breachedChecker := &fakeChecker{breached: true}
	engine1, err := cryden.New(cryden.Config{
		JWTSecret:               "smoketest-jwt-secret",
		Users:                   memory.NewUserStore(),
		Sessions:                memory.NewSessionStore(),
		Audit:                   memory.NewAuditStore(),
		BreachedPasswordChecker: breachedChecker,
	})
	check("engine 1 constructed", err)

	_, err = cryden.SignUp(ctx, engine1, "raymondproguy@dev.com", "password123", "1.2.3.4")
	checkExpectError("signup with a confirmed-breached password is rejected", err)
	if breachedChecker.calls != 1 {
		fail(fmt.Sprintf("expected the checker to be called exactly once, got %d", breachedChecker.calls))
	} else {
		pass("breach checker called exactly once")
	}

	// 2. A checker error fails open — signup still succeeds.
	erroringChecker := &fakeChecker{err: errors.New("simulated HIBP outage")}
	engine2, err := cryden.New(cryden.Config{
		JWTSecret:               "smoketest-jwt-secret-2",
		Users:                   memory.NewUserStore(),
		Sessions:                memory.NewSessionStore(),
		Audit:                   memory.NewAuditStore(),
		BreachedPasswordChecker: erroringChecker,
	})
	check("engine 2 constructed", err)

	_, err = cryden.SignUp(ctx, engine2, "raymondproguy@dev.com", "password123", "1.2.3.4")
	check("signup succeeds when the breach checker itself errors (fail open)", err)

	// 3. A clean password with no breach passes.
	cleanChecker := &fakeChecker{breached: false}
	engine3, err := cryden.New(cryden.Config{
		JWTSecret:               "smoketest-jwt-secret-3",
		Users:                   memory.NewUserStore(),
		Sessions:                memory.NewSessionStore(),
		Audit:                   memory.NewAuditStore(),
		BreachedPasswordChecker: cleanChecker,
	})
	check("engine 3 constructed", err)

	_, err = cryden.SignUp(ctx, engine3, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4")
	check("signup with a clean, non-breached password succeeds", err)

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
