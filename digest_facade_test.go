package cryden

import (
	"context"
	"strings"
	"testing"
	"time"
)

// digestEngineWithHistory builds the same history for every test below:
// one account, one good sign-in, then enough bad ones to trip the
// default lockout — a week that has something in every section a digest
// prints, including one attention-worthy event.
func digestEngineWithHistory(t *testing.T, cfg Config) (*Engine, context.Context) {
	t.Helper()
	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	const (
		email    = "raymondproguy@dev.com"
		password = "Tr0ubl3-Fr33!2026"
	)
	if _, err := SignUp(ctx, engine, email, password, "203.0.113.9"); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, err := Login(ctx, engine, email, password, "203.0.113.9", "test-agent"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	// Five failures is the default LockoutThreshold, so this also
	// records account_locked — the one event type a digest spells out
	// individually rather than only counting.
	for i := 0; i < 5; i++ {
		if _, err := Login(ctx, engine, email, "wrong-password", "198.51.100.7", "test-agent"); err == nil {
			t.Fatal("Login with the wrong password succeeded")
		}
	}
	return engine, ctx
}

func TestWeeklyDigest_SummarisesRealHistory(t *testing.T) {
	engine, ctx := digestEngineWithHistory(t, validConfig())

	text, err := WeeklyDigest(ctx, engine)
	if err != nil {
		t.Fatalf("WeeklyDigest: %v", err)
	}

	for _, want := range []string{
		"Security digest —",
		"(7 days)",
		"Needs attention",
		"1 account was locked after repeated failed sign-ins",
		"Accounts",
		"1 account was created",
		"Sign-ins",
		"1 sign-in succeeded",
		"5 sign-in attempts failed",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("digest is missing %q:\n%s", want, text)
		}
	}

	// The lockout is spelled out, with the IP that caused it — the
	// difference between a digest and a row of numbers.
	if !strings.Contains(text, "IP 198.51.100.7") {
		t.Errorf("the lockout detail line has no IP:\n%s", text)
	}
}

// The reason CountByType went on store.AuditStore rather than into an
// optional side interface: with webhooks configured the engine's audit
// store is a decorator, and a method it did not know to forward would
// leave the digest empty for exactly the hosts that wired webhooks up.
func TestWeeklyDigest_WorksThroughTheWebhookDecoratedAuditStore(t *testing.T) {
	cfg := validConfig()
	sender := &recordingWebhookSender{}
	cfg.Webhooks = sender
	engine, ctx := digestEngineWithHistory(t, cfg)

	text, err := WeeklyDigest(ctx, engine)
	if err != nil {
		t.Fatalf("WeeklyDigest: %v", err)
	}
	if !strings.Contains(text, "1 account was created") || !strings.Contains(text, "5 sign-in attempts failed") {
		t.Errorf("digest lost its history behind the webhook decorator:\n%s", text)
	}
	if len(sender.types()) == 0 {
		t.Error("no webhooks were sent, so this did not exercise the decorated store")
	}
}

func TestWeeklyDigest_QuietEngineSaysNothingToReport(t *testing.T) {
	engine, err := New(validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	text, err := WeeklyDigest(context.Background(), engine)
	if err != nil {
		t.Fatalf("WeeklyDigest: %v", err)
	}
	if !strings.Contains(text, "Nothing to report") {
		t.Errorf("an engine with no history should report nothing:\n%s", text)
	}
}

// A window starting in the future is empty, not an error: DigestSince
// takes whatever bound it is given and reports honestly on it.
func TestDigestSince_FutureWindowIsEmptyNotAnError(t *testing.T) {
	engine, ctx := digestEngineWithHistory(t, validConfig())

	text, err := DigestSince(ctx, engine, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("DigestSince: %v", err)
	}
	if !strings.Contains(text, "Nothing to report") {
		t.Errorf("a future window should hold nothing:\n%s", text)
	}
}

func TestDigestSince_WindowLengthReachesTheHeader(t *testing.T) {
	engine, ctx := digestEngineWithHistory(t, validConfig())

	text, err := DigestSince(ctx, engine, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("DigestSince: %v", err)
	}
	if !strings.Contains(text, "(1 day)") {
		t.Errorf("header does not describe the window asked for:\n%s", text)
	}
}

// Reading a digest twice must not change anything: Tier 4 is read-only,
// and the second read is the cheapest way to prove the first one did not
// record an event of its own.
func TestWeeklyDigest_IsReadOnly(t *testing.T) {
	engine, ctx := digestEngineWithHistory(t, validConfig())

	first, err := WeeklyDigest(ctx, engine)
	if err != nil {
		t.Fatalf("WeeklyDigest: %v", err)
	}
	second, err := WeeklyDigest(ctx, engine)
	if err != nil {
		t.Fatalf("WeeklyDigest: %v", err)
	}

	// The header's "until" moves with the clock, so compare everything
	// after it: the counts must be identical, not one event larger.
	body := func(s string) string { _, rest, _ := strings.Cut(s, "\n"); return rest }
	if body(first) != body(second) {
		t.Errorf("building a digest changed the audit history:\n%s\n---\n%s", first, second)
	}
}
