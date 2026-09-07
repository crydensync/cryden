package cryden

import (
	"context"
	"strings"
	"testing"
)

func TestDiagnoseLoginIssue_LockedAccountThroughRealFlows(t *testing.T) {
	engine, ctx := digestEngineWithHistory(t, validConfig())

	text, err := DiagnoseLoginIssue(ctx, engine, "raymondproguy@dev.com")
	if err != nil {
		t.Fatalf("DiagnoseLoginIssue: %v", err)
	}

	for _, want := range []string{
		"Login diagnosis for raymondproguy@dev.com",
		"Account is LOCKED",
		"account_locked",
		"login_failed",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("diagnosis is missing %q:\n%s", want, text)
		}
	}
}

func TestDiagnoseLoginIssue_UnknownEmailThroughRealFlows(t *testing.T) {
	engine, err := New(validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	text, err := DiagnoseLoginIssue(context.Background(), engine, "nobody@example.com")
	if err != nil {
		t.Fatalf("DiagnoseLoginIssue: %v", err)
	}
	if !strings.Contains(text, "No account exists") {
		t.Errorf("expected 'no account' text, got:\n%s", text)
	}
}

func TestDiagnoseLoginIssue_HealthyAccountHasNoFailureLines(t *testing.T) {
	cfg := validConfig()
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

	text, err := DiagnoseLoginIssue(ctx, engine, email)
	if err != nil {
		t.Fatalf("DiagnoseLoginIssue: %v", err)
	}
	if !strings.Contains(text, "not locked") {
		t.Errorf("expected 'not locked', got:\n%s", text)
	}
	if !strings.Contains(text, "No recent failure-type events") {
		t.Errorf("expected no-failures line, got:\n%s", text)
	}
	if !strings.Contains(text, "1 session is currently active") {
		t.Errorf("expected one active session, got:\n%s", text)
	}
}
