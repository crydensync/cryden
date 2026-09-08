// Command config-tuning-advisor is a standalone, no-database smoke
// test for the config tuning report: turning 30 days of audit history
// and the engine's own current settings into a list of suggested
// changes. What is under test is the whole path through the public
// facade — a default configuration flags the things worth flagging, a
// locked-account-heavy window trips the lockout heuristic, and running
// the report never changes any setting it read.
//
// Run with:
//
//	go run ./cmd/smoketest/config-tuning-advisor
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/crydensync/cryden/v2"
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
	fmt.Println("cryden — config tuning advisor smoke test")

	defaultConfigFlagsWhatsUnconfigured()
	configuredExtrasAreNotFlagged()
	heavyLockoutsAreFlagged()
	reportIsReadOnly()

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
		return
	}
	fmt.Printf("%d CHECK(S) FAILED\n", failures)
	os.Exit(1)
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

func newEngine() (*cryden.Engine, error) {
	return cryden.New(cryden.Config{
		JWTSecret: jwtKey,
		Users:     memory.NewUserStore(),
		Sessions:  memory.NewSessionStore(),
		Audit:     memory.NewAuditStore(),
	})
}

func defaultConfigFlagsWhatsUnconfigured() {
	const section = "default config"
	fmt.Println("\n" + section + ":")
	e, err := newEngine()
	if err != nil {
		check(section, "engine builds", false, err.Error())
		return
	}

	text, err := cryden.ConfigTuningReport(context.Background(), e)
	check(section, "no error building the report", err == nil, fmt.Sprint(err))
	check(section, "flags the default in-memory rate limiter", strings.Contains(text, "Rate limiting"), text)
	check(section, "flags anomaly detection as unconfigured", strings.Contains(text, "Anomaly detection"), text)
	check(section, "flags the missing breached-password checker", strings.Contains(text, "Password strength"), text)
	check(section, "does not flag credential stuffing with anomalies off", !strings.Contains(text, "Credential stuffing"), text)
}

func configuredExtrasAreNotFlagged() {
	const section = "fully configured"
	fmt.Println("\n" + section + ":")
	e, err := cryden.New(cryden.Config{
		JWTSecret: jwtKey,
		Users:     memory.NewUserStore(),
		Sessions:  memory.NewSessionStore(),
		Audit:     memory.NewAuditStore(),
		Anomalies: memory.NewAnomalyStore(),
	})
	if err != nil {
		check(section, "engine builds", false, err.Error())
		return
	}

	text, err := cryden.ConfigTuningReport(context.Background(), e)
	check(section, "no error building the report", err == nil, fmt.Sprint(err))
	check(section, "does not flag anomaly detection as unconfigured", !strings.Contains(text, "is not set, so no login"), text)
}

func heavyLockoutsAreFlagged() {
	const section = "heavy lockouts"
	fmt.Println("\n" + section + ":")
	e, err := newEngine()
	if err != nil {
		check(section, "engine builds", false, err.Error())
		return
	}
	ctx := context.Background()

	// Default LockoutThreshold is 5. Lock several accounts so the
	// account_locked/login_failed ratio clears the heuristic's floor.
	for i := 0; i < 4; i++ {
		email := fmt.Sprintf("user%d@example.com", i)
		if _, err := cryden.SignUp(ctx, e, email, "Tr0ubl3-Fr33!2026", goodIP); err != nil {
			check(section, "signup succeeds", false, err.Error())
			return
		}
		for j := 0; j < 5; j++ {
			_, _ = cryden.Login(ctx, e, email, "wrong-password", badIP, agent)
		}
	}

	text, err := cryden.ConfigTuningReport(context.Background(), e)
	check(section, "no error building the report", err == nil, fmt.Sprint(err))
	check(section, "flags lockout for review", strings.Contains(text, "Lockout"), text)
}

// reportIsReadOnly proves the same non-negotiable rule as the other
// three items in this tier: the report reads settings, it never writes
// one. There's no config-mutation API to call in the first place — this
// confirms building the report repeatedly against unchanged history
// produces the same suggestions every time (not byte-identical text,
// since Until is time.Now() on each call, but the same findings).
func reportIsReadOnly() {
	const section = "read-only"
	fmt.Println("\n" + section + ":")
	e, err := newEngine()
	if err != nil {
		check(section, "engine builds", false, err.Error())
		return
	}
	ctx := context.Background()

	first, err := cryden.ConfigTuningReport(ctx, e)
	if err != nil {
		check(section, "first report succeeds", false, err.Error())
		return
	}
	firstAreas := suggestionAreas(first)

	for i := 0; i < 3; i++ {
		text, err := cryden.ConfigTuningReport(ctx, e)
		if err != nil {
			check(section, fmt.Sprintf("report %d succeeds", i+2), false, err.Error())
			return
		}
		if got := suggestionAreas(text); got != firstAreas {
			check(section, "suggestions stable across repeated reads", false, fmt.Sprintf("first=%q later=%q", firstAreas, got))
			return
		}
	}
	check(section, "suggestions stable across repeated reads", true, "")
}

// suggestionAreas pulls out just the "Area" lines (the ones with no
// leading whitespace, after the header) so two reports can be compared
// on substance without the Since/Until header, which legitimately
// changes call to call.
func suggestionAreas(report string) string {
	var areas []string
	for _, line := range strings.Split(report, "\n") {
		if line == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "Config tuning report") || strings.HasPrefix(line, "Nothing stands out") {
			continue
		}
		areas = append(areas, line)
	}
	return strings.Join(areas, "|")
}
