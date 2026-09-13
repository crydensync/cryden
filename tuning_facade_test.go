package cryden

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/redis/go-redis/v9"
)

func TestConfigTuningReport_DefaultConfigFlagsExpectedAreas(t *testing.T) {
	e, err := New(validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	text, err := ConfigTuningReport(context.Background(), e)
	if err != nil {
		t.Fatalf("ConfigTuningReport: %v", err)
	}

	for _, want := range []string{
		"Rate limiting",     // validConfig sets no custom RateLimiter
		"Anomaly detection", // validConfig sets no Anomalies store
		"Password strength", // validConfig sets no BreachedPasswordChecker
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report is missing %q section:\n%s", want, text)
		}
	}
}

func TestConfigTuningReport_CustomRateLimiterNotFlagged(t *testing.T) {
	limiter, err := security.NewRedisRateLimiter(redis.NewClient(&redis.Options{Addr: "127.0.0.1:0"}), 10, time.Minute)
	if err != nil {
		t.Fatalf("NewRedisRateLimiter: %v", err)
	}
	cfg := validConfig()
	cfg.RateLimiter = limiter
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	text, err := ConfigTuningReport(context.Background(), e)
	if err != nil {
		t.Fatalf("ConfigTuningReport: %v", err)
	}
	if strings.Contains(text, "Rate limiting") {
		t.Errorf("did not expect a Rate limiting suggestion with a custom limiter configured:\n%s", text)
	}
}

func TestConfigTuningReport_AnomaliesConfiguredNotFlaggedAsDisabled(t *testing.T) {
	cfg := validConfig()
	cfg.Anomalies = memory.NewAnomalyStore()
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	text, err := ConfigTuningReport(context.Background(), e)
	if err != nil {
		t.Fatalf("ConfigTuningReport: %v", err)
	}
	if strings.Contains(text, "not screened") || strings.Contains(text, "is not set, so no login") {
		t.Errorf("did not expect the anomalies-disabled finding once Anomalies is configured:\n%s", text)
	}
}

func TestTuningReportSince_EmptyWindowIsNotAnError(t *testing.T) {
	e, err := New(validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// A since in the future: an empty window, not an error, matching
	// DigestSince's own contract.
	text, err := TuningReportSince(context.Background(), e, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("TuningReportSince: %v", err)
	}
	if text == "" {
		t.Error("expected a report even for an empty window, got empty string")
	}
}
