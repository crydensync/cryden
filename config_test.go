package cryden

import (
	"testing"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store/memory"
)

func validConfig() Config {
	return Config{
		JWTSecret: "test-secret",
		Users:     memory.NewUserStore(),
		Sessions:  memory.NewSessionStore(),
		Audit:     memory.NewAuditStore(),
	}
}

func TestNew_Success(t *testing.T) {
	if _, err := New(validConfig()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNew_RejectsMissingJWTSecret(t *testing.T) {
	cfg := validConfig()
	cfg.JWTSecret = ""
	if _, err := New(cfg); err != ErrMissingJWTSecret {
		t.Errorf("expected ErrMissingJWTSecret, got %v", err)
	}
}

func TestNew_RejectsMissingUserStore(t *testing.T) {
	cfg := validConfig()
	cfg.Users = nil
	if _, err := New(cfg); err != ErrMissingUserStore {
		t.Errorf("expected ErrMissingUserStore, got %v", err)
	}
}

func TestNew_RejectsMissingSessionStore(t *testing.T) {
	cfg := validConfig()
	cfg.Sessions = nil
	if _, err := New(cfg); err != ErrMissingSessionStore {
		t.Errorf("expected ErrMissingSessionStore, got %v", err)
	}
}

func TestNew_RejectsMissingAuditStore(t *testing.T) {
	cfg := validConfig()
	cfg.Audit = nil
	if _, err := New(cfg); err != ErrMissingAuditStore {
		t.Errorf("expected ErrMissingAuditStore, got %v", err)
	}
}

func TestNew_AppliesDefaultsWithoutError(t *testing.T) {
	// Zero-valued tuning knobs (TTL, bcrypt cost, rate limit) must be
	// defaulted, not treated as configuration errors — only the
	// security-critical fields (secret, stores) are required.
	cfg := validConfig()
	if _, err := New(cfg); err != nil {
		t.Fatalf("expected zero-valued tuning knobs to default cleanly, got: %v", err)
	}
}

func TestNew_LeavesAPartialCustomPasswordPolicyIntact(t *testing.T) {
	// Regression test: applyDefaults used to detect "unset" via
	// PasswordPolicy.MaxLength == 0 alone, which silently overwrote
	// any custom policy that set MinLength/character requirements but
	// left MaxLength untouched — exactly what a caller would naturally
	// do. Only the fully-zero-value struct should trigger the default.
	cfg := validConfig()
	cfg.PasswordPolicy = security.PasswordPolicy{MinLength: 12, RequireUppercase: true}
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.passwordPolicy.MinLength != 12 {
		t.Errorf("expected MinLength 12 to survive applyDefaults, got %d", e.passwordPolicy.MinLength)
	}
	if !e.passwordPolicy.RequireUppercase {
		t.Error("expected RequireUppercase to survive applyDefaults")
	}
}

func TestNew_AppliesDefaultPasswordPolicyWhenFullyUnset(t *testing.T) {
	cfg := validConfig()
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.passwordPolicy != security.DefaultPasswordPolicy {
		t.Errorf("expected DefaultPasswordPolicy when Config.PasswordPolicy is left unset, got %+v", e.passwordPolicy)
	}
}

func TestNew_AppliesDefaultAnomalyThresholdsWhenFullyUnset(t *testing.T) {
	cfg := validConfig()
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.anomalyThresholds != security.DefaultAnomalyThresholds {
		t.Errorf("expected DefaultAnomalyThresholds when Config.AnomalyThresholds is unset, got %+v", e.anomalyThresholds)
	}
}

func TestNew_LeavesPartialCustomAnomalyThresholdsIntact(t *testing.T) {
	// Same whole-struct zero comparison as PasswordPolicy: a caller who
	// tunes one knob must not have the rest silently replaced.
	cfg := validConfig()
	cfg.AnomalyThresholds = security.AnomalyThresholds{UserFailureVelocity: 3}
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.anomalyThresholds.UserFailureVelocity != 3 {
		t.Errorf("expected UserFailureVelocity 3 to survive applyDefaults, got %d", e.anomalyThresholds.UserFailureVelocity)
	}
	if e.anomalyThresholds.IPFailureVelocity != 0 {
		t.Errorf("expected the untouched fields to stay zero, got %d", e.anomalyThresholds.IPFailureVelocity)
	}
}

// Anomaly detection is off until a store is injected, like every other
// optional feature. An engine without one must build and work normally.
func TestNew_AnomalyDetectionIsOffWithoutAStore(t *testing.T) {
	cfg := validConfig()
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.anomalies != nil {
		t.Error("expected no AnomalyStore when Config.Anomalies is unset")
	}
}

func TestNew_AcceptsAnAnomalyStore(t *testing.T) {
	cfg := validConfig()
	cfg.Anomalies = memory.NewAnomalyStore()
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.anomalies == nil {
		t.Error("expected Config.Anomalies to reach the engine")
	}
}
