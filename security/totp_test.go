package security

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestPquernaTOTPGenerator_NewSecretReturnsUsableSecretAndURL(t *testing.T) {
	gen := NewPquernaTOTPGenerator()

	secret, url, err := gen.NewSecret("CrydenSync", "user@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret == "" {
		t.Error("expected a non-empty secret")
	}
	if url == "" {
		t.Error("expected a non-empty otpauth:// URL")
	}
}

func TestPquernaTOTPGenerator_ValidateAcceptsCorrectCode(t *testing.T) {
	gen := NewPquernaTOTPGenerator()
	secret, _, err := gen.NewSecret("CrydenSync", "user@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	now := time.Now()
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatalf("failed to generate a real code: %v", err)
	}

	if !gen.Validate(secret, code, now) {
		t.Error("expected a correctly generated code to validate")
	}
}

func TestPquernaTOTPGenerator_ValidateRejectsWrongCode(t *testing.T) {
	gen := NewPquernaTOTPGenerator()
	secret, _, _ := gen.NewSecret("CrydenSync", "user@example.com")

	if gen.Validate(secret, "000000", time.Now()) {
		t.Error("expected an arbitrary wrong code to be rejected (astronomically unlikely to collide)")
	}
}

func TestPquernaTOTPGenerator_ValidateRejectsExpiredCode(t *testing.T) {
	gen := NewPquernaTOTPGenerator()
	secret, _, _ := gen.NewSecret("CrydenSync", "user@example.com")

	past := time.Now().Add(-10 * time.Minute)
	code, _ := totp.GenerateCode(secret, past)

	if gen.Validate(secret, code, time.Now()) {
		t.Error("expected a code from 10 minutes ago to be rejected — well outside the ±1 step skew window")
	}
}
