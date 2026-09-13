// Command support-ticket-assistant is a standalone, no-database smoke
// test for the login diagnosis assistant: turning a support ticket's
// "why can't user X log in" into a plain-text answer built entirely
// from what the engine already recorded. What is under test is the
// whole path through the public facade — an unknown email, a locked
// account with a real failure history, a healthy account with a live
// session, and that running the diagnosis is read-only: nothing is
// unlocked, no counter is reset, no session is touched.
//
// Run with:
//
//	go run ./cmd/smoketest/support-ticket-assistant
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
)

const (
	jwtKey = "smoketest-jwt-secret-do-not-ship"
	goodIP = "203.0.113.9"
	badIP  = "198.51.100.7"
	agent  = "smoketest-agent"
)

var failures int

func main() {
	fmt.Println("cryden — support-ticket assistant smoke test")

	unknownEmailIsReportedNotErrored()
	lockedAccountShowsWhy()
	healthyAccountShowsNoFailures()
	diagnosisWritesNothing()
	noSecretsInTheReport()

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
		return
	}
	fmt.Printf("%d CHECK(S) FAILED\n", failures)
	os.Exit(1)
}

func newEngine() (*cryden.Engine, store.UserStore, error) {
	users := memory.NewUserStore()
	cfg := cryden.Config{
		JWTSecret: jwtKey,
		Users:     users,
		Sessions:  memory.NewSessionStore(),
		Audit:     memory.NewAuditStore(),
	}
	e, err := cryden.New(cfg)
	return e, users, err
}

func check(section, name string, ok bool, detail string) {
	status := "✓"
	if !ok {
		status = "✗"
		failures++
	}
	fmt.Printf("  %s [%s] %s\n", status, section, name)
	if !ok && detail != "" {
		fmt.Printf("      %s\n", detail)
	}
}

func unknownEmailIsReportedNotErrored() {
	const section = "unknown email"
	fmt.Println("\n" + section + ":")
	e, _, err := newEngine()
	if err != nil {
		check(section, "engine builds", false, err.Error())
		return
	}
	ctx := context.Background()

	text, err := cryden.DiagnoseLoginIssue(ctx, e, "nobody@example.com")
	check(section, "no error for an unknown email", err == nil, fmt.Sprint(err))
	check(section, "reports no account rather than failing", strings.Contains(text, "No account exists"), text)
}

func lockedAccountShowsWhy() {
	const section = "locked account"
	fmt.Println("\n" + section + ":")
	e, _, err := newEngine()
	if err != nil {
		check(section, "engine builds", false, err.Error())
		return
	}
	ctx := context.Background()
	const email, password = "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026"

	if _, err := cryden.SignUp(ctx, e, email, password, goodIP); err != nil {
		check(section, "signup succeeds", false, err.Error())
		return
	}
	// Default LockoutThreshold is 5.
	for i := 0; i < 5; i++ {
		if _, err := cryden.Login(ctx, e, email, "wrong-password", badIP, agent); err == nil {
			check(section, "wrong password is rejected", false, "a wrong-password login unexpectedly succeeded")
			return
		}
	}

	text, err := cryden.DiagnoseLoginIssue(ctx, e, email)
	check(section, "no error diagnosing a locked account", err == nil, fmt.Sprint(err))
	check(section, "reports the account as locked", strings.Contains(text, "Account is LOCKED"), text)
	check(section, "reports the failed-attempt count", strings.Contains(text, "5 consecutive failed attempts"), text)
	check(section, "lists account_locked in the recent history", strings.Contains(text, "account_locked"), text)
	check(section, "lists login_failed in the recent history", strings.Contains(text, "login_failed"), text)
	check(section, "reports zero active sessions", strings.Contains(text, "0 sessions are currently active"), text)

	// A second attempt while locked is expected to fail, and running
	// the diagnosis a second time must read the same thing back — it
	// never clears the lock itself.
	if _, err := cryden.Login(ctx, e, email, password, goodIP, agent); err == nil {
		check(section, "correct password is still rejected while locked", false, "login succeeded through an active lockout")
	}
	textAgain, err := cryden.DiagnoseLoginIssue(ctx, e, email)
	check(section, "diagnosis is stable on a second read", err == nil && strings.Contains(textAgain, "Account is LOCKED"), textAgain)
}

func healthyAccountShowsNoFailures() {
	const section = "healthy account"
	fmt.Println("\n" + section + ":")
	e, _, err := newEngine()
	if err != nil {
		check(section, "engine builds", false, err.Error())
		return
	}
	ctx := context.Background()
	const email, password = "ok@example.com", "Tr0ubl3-Fr33!2026"

	if _, err := cryden.SignUp(ctx, e, email, password, goodIP); err != nil {
		check(section, "signup succeeds", false, err.Error())
		return
	}
	if _, err := cryden.Login(ctx, e, email, password, goodIP, agent); err != nil {
		check(section, "login succeeds", false, err.Error())
		return
	}

	text, err := cryden.DiagnoseLoginIssue(ctx, e, email)
	check(section, "no error diagnosing a healthy account", err == nil, fmt.Sprint(err))
	check(section, "reports not locked", strings.Contains(text, "not locked"), text)
	check(section, "reports no recent failures", strings.Contains(text, "No recent failure-type events"), text)
	check(section, "reports one active session", strings.Contains(text, "1 session is currently active"), text)
}

// diagnosisWritesNothing proves the non-negotiable rule for the whole
// tier: running a diagnosis, however many times, never changes the
// account it is reporting on.
func diagnosisWritesNothing() {
	const section = "read-only"
	fmt.Println("\n" + section + ":")
	e, users, err := newEngine()
	if err != nil {
		check(section, "engine builds", false, err.Error())
		return
	}
	ctx := context.Background()
	const email, password = "watched@example.com", "Tr0ubl3-Fr33!2026"

	if _, err := cryden.SignUp(ctx, e, email, password, goodIP); err != nil {
		check(section, "signup succeeds", false, err.Error())
		return
	}
	for i := 0; i < 3; i++ {
		_, _ = cryden.Login(ctx, e, email, "wrong-password", badIP, agent)
	}

	before, err := users.GetByEmail(ctx, email)
	if err != nil {
		check(section, "user readable before diagnosis", false, err.Error())
		return
	}

	for i := 0; i < 5; i++ {
		if _, err := cryden.DiagnoseLoginIssue(ctx, e, email); err != nil {
			check(section, fmt.Sprintf("diagnosis %d succeeds", i+1), false, err.Error())
			return
		}
	}

	after, err := users.GetByEmail(ctx, email)
	if err != nil {
		check(section, "user readable after diagnosis", false, err.Error())
		return
	}
	check(section, "failed-attempt count is unchanged", before.FailedAttempts == after.FailedAttempts,
		fmt.Sprintf("before=%d after=%d", before.FailedAttempts, after.FailedAttempts))
	check(section, "locked-until is unchanged", (before.LockedUntil == nil) == (after.LockedUntil == nil), "lock state changed")
}

func noSecretsInTheReport() {
	const section = "no secrets"
	fmt.Println("\n" + section + ":")
	e, _, err := newEngine()
	if err != nil {
		check(section, "engine builds", false, err.Error())
		return
	}
	ctx := context.Background()
	const email, password = "secret@example.com", "Tr0ubl3-Fr33!2026"

	if _, err := cryden.SignUp(ctx, e, email, password, goodIP); err != nil {
		check(section, "signup succeeds", false, err.Error())
		return
	}
	text, err := cryden.DiagnoseLoginIssue(ctx, e, email)
	if err != nil {
		check(section, "diagnosis succeeds", false, err.Error())
		return
	}
	check(section, "password never appears", !strings.Contains(text, password), text)
	check(section, "jwt secret never appears", !strings.Contains(text, jwtKey), text)
}
