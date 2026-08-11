package cryden

import (
	"testing"

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
