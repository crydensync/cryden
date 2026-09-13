package cryden

import (
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/redis/go-redis/v9"
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

func TestNew_AppliesDefaultCredentialStuffingThresholdsWhenFullyUnset(t *testing.T) {
	cfg := validConfig()
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.stuffingThresholds != security.DefaultCredentialStuffingThresholds {
		t.Errorf("expected DefaultCredentialStuffingThresholds when Config.CredentialStuffingThresholds is unset, got %+v", e.stuffingThresholds)
	}
}

func TestNew_LeavesPartialCustomCredentialStuffingThresholdsIntact(t *testing.T) {
	cfg := validConfig()
	cfg.CredentialStuffingThresholds = security.CredentialStuffingThresholds{TargetAccounts: 50}
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.stuffingThresholds.TargetAccounts != 50 {
		t.Errorf("expected TargetAccounts 50 to survive applyDefaults, got %d", e.stuffingThresholds.TargetAccounts)
	}
	if e.stuffingThresholds.Cooldown != 0 {
		t.Errorf("expected the untouched fields to stay zero, got %v", e.stuffingThresholds.Cooldown)
	}
}

// The two threshold structs default independently, which is the whole
// reason they are two structs: tuning anomaly detection must not zero —
// and so silently disable — credential-stuffing detection, or the other
// way round.
func TestNew_TheTwoDetectionThresholdsDefaultIndependently(t *testing.T) {
	cfg := validConfig()
	cfg.AnomalyThresholds = security.AnomalyThresholds{UserFailureVelocity: 3}
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.stuffingThresholds != security.DefaultCredentialStuffingThresholds {
		t.Errorf("a custom AnomalyThresholds must leave stuffing defaults alone, got %+v", e.stuffingThresholds)
	}

	cfg = validConfig()
	cfg.CredentialStuffingThresholds = security.CredentialStuffingThresholds{TargetAccounts: 50}
	e, err = New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.anomalyThresholds != security.DefaultAnomalyThresholds {
		t.Errorf("a custom CredentialStuffingThresholds must leave anomaly defaults alone, got %+v", e.anomalyThresholds)
	}
}

// Geolocation is off until a host supplies an implementation, exactly
// like BreachedPasswordChecker — the engine ships none.
func TestNew_GeolocationIsOffWithoutAnImplementation(t *testing.T) {
	e, err := New(validConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.geolocator != nil {
		t.Error("expected no IPGeolocator when Config.Geolocator is unset")
	}
}

func TestNew_AcceptsAGeolocator(t *testing.T) {
	cfg := validConfig()
	cfg.Geolocator = fixedGeolocator{}
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.geolocator == nil {
		t.Error("expected Config.Geolocator to reach the engine")
	}
}

// The in-process limiter stays the default: it needs no infrastructure,
// and every existing caller gets exactly what it got before.
func TestNew_DefaultsToTheInProcessRateLimiter(t *testing.T) {
	e, err := New(validConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := e.rateLimiter.(*security.InMemoryRateLimiter); !ok {
		t.Errorf("expected an InMemoryRateLimiter by default, got %T", e.rateLimiter)
	}
}

func TestNew_AcceptsACustomRateLimiter(t *testing.T) {
	limiter := &stubRateLimiter{allow: true}
	cfg := validConfig()
	cfg.RateLimiter = limiter
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.rateLimiter != limiter {
		t.Errorf("expected Config.RateLimiter to reach the engine, got %T", e.rateLimiter)
	}
}

// The integration a host app actually writes, compiled and wired here so
// it cannot rot. No Redis is contacted: go-redis dials lazily on the
// first command, and constructing an engine issues none.
func TestNew_AcceptsARedisRateLimiter(t *testing.T) {
	limiter, err := security.NewRedisRateLimiter(
		redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"}),
		10,
		time.Minute,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg := validConfig()
	cfg.RateLimiter = limiter
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.rateLimiter != limiter {
		t.Errorf("expected the Redis limiter to reach the engine, got %T", e.rateLimiter)
	}
}
