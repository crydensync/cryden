package security

import "testing"

func TestPasswordPolicy_Validate_AllViolationsReportedTogether(t *testing.T) {
	policy := PasswordPolicy{
		MinLength:        8,
		MaxLength:        72,
		RequireUppercase: true,
		RequireDigit:     true,
	}

	violations := policy.Validate("abc")
	want := map[string]bool{"min_length": true, "require_uppercase": true, "require_digit": true}
	if len(violations) != len(want) {
		t.Fatalf("expected %d violations, got %d: %v", len(want), len(violations), violations)
	}
	for _, v := range violations {
		if !want[v] {
			t.Errorf("unexpected violation code: %q", v)
		}
	}
}

func TestPasswordPolicy_Validate_PassesAGoodPassword(t *testing.T) {
	policy := DefaultPasswordPolicy
	if violations := policy.Validate("Tr0ubl3-Fr33!2026"); len(violations) != 0 {
		t.Errorf("expected no violations, got %v", violations)
	}
}

func TestPasswordPolicy_Validate_MaxLengthZeroMeansUnbounded(t *testing.T) {
	policy := PasswordPolicy{MinLength: 1, MaxLength: 0}
	longPassword := make([]byte, 500)
	for i := range longPassword {
		longPassword[i] = 'a'
	}
	if violations := policy.Validate(string(longPassword)); len(violations) != 0 {
		t.Errorf("expected MaxLength 0 to mean no upper bound, got violations: %v", violations)
	}
}

func TestPasswordPolicy_Validate_RequireSymbol(t *testing.T) {
	policy := PasswordPolicy{RequireSymbol: true}
	if violations := policy.Validate("alllettersandnumbers123"); len(violations) == 0 {
		t.Error("expected require_symbol violation for a password with no symbols")
	}
	if violations := policy.Validate("has-a-dash"); len(violations) != 0 {
		t.Errorf("expected a dash to satisfy require_symbol, got violations: %v", violations)
	}
}

func TestDefaultPasswordPolicy_RejectsShortPasswords(t *testing.T) {
	violations := DefaultPasswordPolicy.Validate("short1")
	found := false
	for _, v := range violations {
		if v == "min_length" {
			found = true
		}
	}
	if !found {
		t.Error("expected min_length violation for a 6-character password against the default policy")
	}
}

func TestDefaultPasswordPolicy_RejectsOver72Bytes(t *testing.T) {
	longPassword := make([]byte, 73)
	for i := range longPassword {
		longPassword[i] = 'a'
	}
	violations := DefaultPasswordPolicy.Validate(string(longPassword))
	found := false
	for _, v := range violations {
		if v == "max_length" {
			found = true
		}
	}
	if !found {
		t.Error("expected max_length violation for a 73-byte password against the default policy (bcrypt's real limit is 72)")
	}
}
