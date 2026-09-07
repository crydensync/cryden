package admin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// fakeUserByEmailReader is the whole store a diagnosis is allowed to
// see for user lookup — no Create, no LockAccount, no
// ResetFailedAttempts.
type fakeUserByEmailReader struct {
	users map[string]store.User
	err   error
}

func (f *fakeUserByEmailReader) GetByEmail(ctx context.Context, email string) (store.User, error) {
	if f.err != nil {
		return store.User{}, f.err
	}
	u, ok := f.users[email]
	if !ok {
		return store.User{}, store.ErrNotFound
	}
	return u, nil
}

var _ UserByEmailReader = (*fakeUserByEmailReader)(nil)

// fakeUserAuditHistoryReader is the whole store a diagnosis is allowed
// to see for one account's history — no Record.
type fakeUserAuditHistoryReader struct {
	events map[string][]store.AuditEvent
	err    error
}

func (f *fakeUserAuditHistoryReader) ListByUser(ctx context.Context, userID string, limit int) ([]store.AuditEvent, error) {
	if f.err != nil {
		return nil, f.err
	}
	events := f.events[userID]
	if len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

var _ UserAuditHistoryReader = (*fakeUserAuditHistoryReader)(nil)

// fakeUserSessionReader is the whole store a diagnosis is allowed to
// see for an account's live sessions — no Revoke, no
// RevokeAllForUser.
type fakeUserSessionReader struct {
	sessions map[string][]store.Session
	err      error
}

func (f *fakeUserSessionReader) ListByUser(ctx context.Context, userID string) ([]store.Session, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.sessions[userID], nil
}

var _ UserSessionReader = (*fakeUserSessionReader)(nil)

func TestDiagnoseLogin_NoSuchAccount(t *testing.T) {
	users := &fakeUserByEmailReader{users: map[string]store.User{}}
	audit := &fakeUserAuditHistoryReader{}
	sessions := &fakeUserSessionReader{}

	d, err := DiagnoseLogin(context.Background(), users, audit, sessions, "nobody@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Found {
		t.Fatal("expected Found=false for an email with no account")
	}
	if !strings.Contains(d.Text(), "No account exists") {
		t.Errorf("expected the text to say no account exists, got:\n%s", d.Text())
	}
}

func TestDiagnoseLogin_LockedAccountWithRecentFailures(t *testing.T) {
	until := time.Now().Add(10 * time.Minute)
	users := &fakeUserByEmailReader{users: map[string]store.User{
		"locked@example.com": {ID: "u1", Email: "locked@example.com", FailedAttempts: 5, LockedUntil: &until},
	}}
	failedAt := time.Now().Add(-time.Minute)
	audit := &fakeUserAuditHistoryReader{events: map[string][]store.AuditEvent{
		"u1": {
			{Type: store.EventAccountLocked, UserID: "u1", IP: "198.51.100.7", CreatedAt: failedAt},
			{Type: store.EventLoginFailed, UserID: "u1", IP: "198.51.100.7", CreatedAt: failedAt.Add(-time.Second)},
			{Type: store.EventLoginSuccess, UserID: "u1", CreatedAt: failedAt.Add(-time.Hour)},
		},
	}}
	sessions := &fakeUserSessionReader{sessions: map[string][]store.Session{}}

	d, err := DiagnoseLogin(context.Background(), users, audit, sessions, "locked@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.Found || !d.Locked {
		t.Fatalf("expected Found and Locked, got %+v", d)
	}
	if d.FailedAttempts != 5 {
		t.Errorf("expected 5 failed attempts, got %d", d.FailedAttempts)
	}
	if d.ActiveSessions != 0 {
		t.Errorf("expected 0 active sessions, got %d", d.ActiveSessions)
	}

	text := d.Text()
	for _, want := range []string{
		"Account is LOCKED",
		"5 consecutive failed attempts",
		"0 sessions are currently active",
		"account_locked",
		"login_failed",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("diagnosis text missing %q:\n%s", want, text)
		}
	}
	// The successful login is real history but not a failure-type
	// event, so it must not appear among the recent-failures lines.
	if strings.Contains(text, "login_success") {
		t.Errorf("diagnosis should not list login_success as a failure event:\n%s", text)
	}
}

func TestDiagnoseLogin_HealthyAccountNoRecentFailures(t *testing.T) {
	users := &fakeUserByEmailReader{users: map[string]store.User{
		"ok@example.com": {ID: "u2", Email: "ok@example.com", FailedAttempts: 0},
	}}
	audit := &fakeUserAuditHistoryReader{events: map[string][]store.AuditEvent{
		"u2": {{Type: store.EventLoginSuccess, UserID: "u2", CreatedAt: time.Now()}},
	}}
	sessions := &fakeUserSessionReader{sessions: map[string][]store.Session{
		"u2": {{ID: "s1", UserID: "u2"}},
	}}

	d, err := DiagnoseLogin(context.Background(), users, audit, sessions, "ok@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Locked {
		t.Error("expected an unlocked account")
	}
	if d.ActiveSessions != 1 {
		t.Errorf("expected 1 active session, got %d", d.ActiveSessions)
	}
	text := d.Text()
	if !strings.Contains(text, "not locked") {
		t.Errorf("expected 'not locked' in text:\n%s", text)
	}
	if !strings.Contains(text, "No recent failure-type events") {
		t.Errorf("expected no-failures line in text:\n%s", text)
	}
}

func TestDiagnoseLogin_ExpiredLockIsNotReportedAsLocked(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	users := &fakeUserByEmailReader{users: map[string]store.User{
		"was-locked@example.com": {ID: "u3", Email: "was-locked@example.com", LockedUntil: &past},
	}}
	audit := &fakeUserAuditHistoryReader{}
	sessions := &fakeUserSessionReader{}

	d, err := DiagnoseLogin(context.Background(), users, audit, sessions, "was-locked@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Locked {
		t.Error("a LockedUntil in the past must not be reported as currently locked")
	}
}

func TestDiagnoseLogin_UserStoreErrorPropagates(t *testing.T) {
	boom := errors.New("boom")
	users := &fakeUserByEmailReader{err: boom}
	_, err := DiagnoseLogin(context.Background(), users, &fakeUserAuditHistoryReader{}, &fakeUserSessionReader{}, "x@example.com")
	if err == nil {
		t.Fatal("expected an error to propagate")
	}
}

func TestDiagnoseLogin_SessionStoreErrorPropagates(t *testing.T) {
	users := &fakeUserByEmailReader{users: map[string]store.User{
		"x@example.com": {ID: "u4"},
	}}
	sessions := &fakeUserSessionReader{err: errors.New("boom")}
	_, err := DiagnoseLogin(context.Background(), users, &fakeUserAuditHistoryReader{}, sessions, "x@example.com")
	if err == nil {
		t.Fatal("expected an error to propagate")
	}
}

func TestDiagnoseLogin_AuditStoreErrorPropagates(t *testing.T) {
	users := &fakeUserByEmailReader{users: map[string]store.User{
		"x@example.com": {ID: "u5"},
	}}
	audit := &fakeUserAuditHistoryReader{err: errors.New("boom")}
	_, err := DiagnoseLogin(context.Background(), users, audit, &fakeUserSessionReader{}, "x@example.com")
	if err == nil {
		t.Fatal("expected an error to propagate")
	}
}
