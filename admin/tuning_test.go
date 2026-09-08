package admin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

func baseTuningInputs() TuningInputs {
	return TuningInputs{
		LockoutThreshold:              5,
		LockoutDuration:               15 * time.Minute,
		RateLimitAttempts:             10,
		RateLimitWindow:               time.Minute,
		UsingDefaultRateLimiter:       false,
		AnomaliesEnabled:              true,
		UserFailureVelocity:           5,
		IPFailureVelocity:             20,
		HistorySize:                   20,
		StuffingTargetAccounts:        10,
		StuffingWindow:                time.Hour,
		StuffingCooldown:              15 * time.Minute,
		BreachedPasswordCheckerActive: true,
	}
}

func areas(suggestions []TuningSuggestion) []string {
	var out []string
	for _, s := range suggestions {
		out = append(out, s.Area)
	}
	return out
}

func contains(areas []string, area string) bool {
	for _, a := range areas {
		if a == area {
			return true
		}
	}
	return false
}

func TestBuildTuningReport_CleanWindowSuggestsNothing(t *testing.T) {
	reader := &fakeAuditReader{counts: map[store.AuditEventType]int{
		store.EventLoginSuccess: 10,
		store.EventLoginFailed:  2,
	}}
	report, err := BuildTuningReport(context.Background(), reader, baseTuningInputs(), time.Now().Add(-DefaultTuningWindow))
	if err != nil {
		t.Fatalf("BuildTuningReport: %v", err)
	}
	if len(report.Suggestions) != 0 {
		t.Errorf("expected no suggestions, got %v", areas(report.Suggestions))
	}
	if !strings.Contains(report.Text(), "Nothing stands out") {
		t.Errorf("Text() should say nothing stands out, got:\n%s", report.Text())
	}
}

func TestBuildTuningReport_HighLockoutRatioSuggestsReview(t *testing.T) {
	reader := &fakeAuditReader{counts: map[store.AuditEventType]int{
		store.EventLoginFailed:   40,
		store.EventAccountLocked: 8, // 20% of failures result in a lock
	}}
	report, err := BuildTuningReport(context.Background(), reader, baseTuningInputs(), time.Now().Add(-DefaultTuningWindow))
	if err != nil {
		t.Fatalf("BuildTuningReport: %v", err)
	}
	if !contains(areas(report.Suggestions), "Lockout") {
		t.Errorf("expected a Lockout suggestion, got %v", areas(report.Suggestions))
	}
}

func TestBuildTuningReport_LowLockoutCountIsIgnoredEvenAtHighRatio(t *testing.T) {
	// 2 locks out of 4 failures is a very high ratio, but too small a
	// sample to mean anything — must not fire.
	reader := &fakeAuditReader{counts: map[store.AuditEventType]int{
		store.EventLoginFailed:   4,
		store.EventAccountLocked: 2,
	}}
	report, err := BuildTuningReport(context.Background(), reader, baseTuningInputs(), time.Now().Add(-DefaultTuningWindow))
	if err != nil {
		t.Fatalf("BuildTuningReport: %v", err)
	}
	if contains(areas(report.Suggestions), "Lockout") {
		t.Errorf("expected no Lockout suggestion on a tiny sample, got %v", areas(report.Suggestions))
	}
}

func TestBuildTuningReport_DefaultRateLimiterFlagged(t *testing.T) {
	reader := &fakeAuditReader{counts: map[store.AuditEventType]int{}}
	in := baseTuningInputs()
	in.UsingDefaultRateLimiter = true
	report, err := BuildTuningReport(context.Background(), reader, in, time.Now().Add(-DefaultTuningWindow))
	if err != nil {
		t.Fatalf("BuildTuningReport: %v", err)
	}
	if !contains(areas(report.Suggestions), "Rate limiting") {
		t.Errorf("expected a Rate limiting suggestion, got %v", areas(report.Suggestions))
	}
}

func TestBuildTuningReport_CustomRateLimiterNotFlagged(t *testing.T) {
	reader := &fakeAuditReader{counts: map[store.AuditEventType]int{}}
	in := baseTuningInputs()
	in.UsingDefaultRateLimiter = false
	report, err := BuildTuningReport(context.Background(), reader, in, time.Now().Add(-DefaultTuningWindow))
	if err != nil {
		t.Fatalf("BuildTuningReport: %v", err)
	}
	if contains(areas(report.Suggestions), "Rate limiting") {
		t.Errorf("expected no Rate limiting suggestion with a custom limiter configured")
	}
}

func TestBuildTuningReport_AnomaliesDisabledIsFlagged(t *testing.T) {
	reader := &fakeAuditReader{counts: map[store.AuditEventType]int{}}
	in := baseTuningInputs()
	in.AnomaliesEnabled = false
	report, err := BuildTuningReport(context.Background(), reader, in, time.Now().Add(-DefaultTuningWindow))
	if err != nil {
		t.Fatalf("BuildTuningReport: %v", err)
	}
	if !contains(areas(report.Suggestions), "Anomaly detection") {
		t.Errorf("expected an Anomaly detection suggestion when disabled, got %v", areas(report.Suggestions))
	}
	// Credential-stuffing has nothing to say when anomaly detection
	// (which owns the same store) is off entirely.
	found := 0
	for _, s := range report.Suggestions {
		if s.Area == "Credential stuffing" {
			found++
		}
	}
	if found != 0 {
		t.Errorf("expected no Credential stuffing suggestion when anomalies are disabled")
	}
}

func TestBuildTuningReport_AnomaliesSilentWithRealVolumeIsFlagged(t *testing.T) {
	reader := &fakeAuditReader{counts: map[store.AuditEventType]int{
		store.EventLoginSuccess: 500,
	}}
	report, err := BuildTuningReport(context.Background(), reader, baseTuningInputs(), time.Now().Add(-DefaultTuningWindow))
	if err != nil {
		t.Fatalf("BuildTuningReport: %v", err)
	}
	if !contains(areas(report.Suggestions), "Anomaly detection") {
		t.Errorf("expected an Anomaly detection suggestion for silence at volume, got %v", areas(report.Suggestions))
	}
}

func TestBuildTuningReport_AnomaliesQuietWithLowVolumeIsNotFlagged(t *testing.T) {
	reader := &fakeAuditReader{counts: map[store.AuditEventType]int{
		store.EventLoginSuccess: 3,
	}}
	report, err := BuildTuningReport(context.Background(), reader, baseTuningInputs(), time.Now().Add(-DefaultTuningWindow))
	if err != nil {
		t.Fatalf("BuildTuningReport: %v", err)
	}
	if contains(areas(report.Suggestions), "Anomaly detection") {
		t.Errorf("expected no Anomaly detection suggestion at low volume, got %v", areas(report.Suggestions))
	}
}

func TestBuildTuningReport_HighAnomalyShareIsFlagged(t *testing.T) {
	reader := &fakeAuditReader{counts: map[store.AuditEventType]int{
		store.EventLoginSuccess:    100,
		store.EventAnomalyDetected: 30,
	}}
	report, err := BuildTuningReport(context.Background(), reader, baseTuningInputs(), time.Now().Add(-DefaultTuningWindow))
	if err != nil {
		t.Fatalf("BuildTuningReport: %v", err)
	}
	if !contains(areas(report.Suggestions), "Anomaly detection") {
		t.Errorf("expected an Anomaly detection suggestion for a high flagged share, got %v", areas(report.Suggestions))
	}
}

func TestBuildTuningReport_CredentialStuffingBurstsFlaggedWhenAnomaliesOn(t *testing.T) {
	reader := &fakeAuditReader{counts: map[store.AuditEventType]int{
		store.EventCredentialStuffingDetected: 3,
	}}
	report, err := BuildTuningReport(context.Background(), reader, baseTuningInputs(), time.Now().Add(-DefaultTuningWindow))
	if err != nil {
		t.Fatalf("BuildTuningReport: %v", err)
	}
	if !contains(areas(report.Suggestions), "Credential stuffing") {
		t.Errorf("expected a Credential stuffing suggestion, got %v", areas(report.Suggestions))
	}
}

func TestBuildTuningReport_NoBreachedPasswordCheckerIsFlagged(t *testing.T) {
	reader := &fakeAuditReader{counts: map[store.AuditEventType]int{}}
	in := baseTuningInputs()
	in.BreachedPasswordCheckerActive = false
	report, err := BuildTuningReport(context.Background(), reader, in, time.Now().Add(-DefaultTuningWindow))
	if err != nil {
		t.Fatalf("BuildTuningReport: %v", err)
	}
	if !contains(areas(report.Suggestions), "Password strength") {
		t.Errorf("expected a Password strength suggestion, got %v", areas(report.Suggestions))
	}
}

func TestBuildTuningReport_BreachedPasswordRejectionsAreInformational(t *testing.T) {
	reader := &fakeAuditReader{counts: map[store.AuditEventType]int{
		store.EventPasswordBreachRejected: 2,
	}}
	report, err := BuildTuningReport(context.Background(), reader, baseTuningInputs(), time.Now().Add(-DefaultTuningWindow))
	if err != nil {
		t.Fatalf("BuildTuningReport: %v", err)
	}
	var found *TuningSuggestion
	for i := range report.Suggestions {
		if report.Suggestions[i].Area == "Password strength" {
			found = &report.Suggestions[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a Password strength suggestion, got %v", areas(report.Suggestions))
	}
	if !strings.Contains(found.Suggestion, "No change suggested") {
		t.Errorf("expected an informational, no-change suggestion, got: %s", found.Suggestion)
	}
}

func TestBuildTuningReport_ReaderErrorPropagates(t *testing.T) {
	reader := &fakeAuditReader{countErr: errors.New("db down")}
	_, err := BuildTuningReport(context.Background(), reader, baseTuningInputs(), time.Now().Add(-DefaultTuningWindow))
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestBuildTuningReport_NeverCallsSearchByType(t *testing.T) {
	// A tuning report is aggregate-only; per-event detail is the
	// digest's job (item 19), not this one's.
	reader := &fakeAuditReader{counts: map[store.AuditEventType]int{
		store.EventLoginFailed:   40,
		store.EventAccountLocked: 8,
	}}
	if _, err := BuildTuningReport(context.Background(), reader, baseTuningInputs(), time.Now().Add(-DefaultTuningWindow)); err != nil {
		t.Fatalf("BuildTuningReport: %v", err)
	}
	if len(reader.searched) != 0 {
		t.Errorf("expected no SearchByType calls, got %v", reader.searched)
	}
}
