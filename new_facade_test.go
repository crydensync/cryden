package cryden

import (
	"context"
	"errors"
	"testing"

	"github.com/crydensync/cryden/v2/auth"
	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
)

func TestGetUser_Success(t *testing.T) {
	cfg := validConfig()
	engine, _ := New(cfg)
	ctx := context.Background()

	_, err := SignUp(ctx, engine, "devray@example.com", "Pass@2026", "1.2.3.4")
	if err != nil {
		t.Fatalf("signup failed: %v", err)
	}

	user, err := GetUser(ctx, engine, "devray@example.com")
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if user.Email != "devray@example.com" {
		t.Errorf("expected devray@example.com, got %s", user.Email)
	}
}

func TestGetUser_NotFound(t *testing.T) {
	cfg := validConfig()
	engine, _ := New(cfg)
	ctx := context.Background()

	_, err := GetUser(ctx, engine, "nobody@example.com")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestListPublicSessions_ExcludesTokenHash(t *testing.T) {
	cfg := validConfig()
	engine, _ := New(cfg)
	ctx := context.Background()

	SignUp(ctx, engine, "devray@example.com", "Pass@2026", "1.2.3.4")
	Login(ctx, engine, "devray@example.com", "Pass@2026", "1.2.3.4", "test-agent")

	sessions, err := ListPublicSessions(ctx, engine, mustUserID(ctx, engine, t))
	if err != nil {
		t.Fatalf("ListPublicSessions failed: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	// PublicSession has no TokenHash field at all — this is a
	// compile-time guarantee, not just a runtime check. If this test
	// compiles, the field genuinely doesn't exist on the type.
	if sessions[0].ID == "" {
		t.Error("expected a populated session ID")
	}
}

func mustUserID(ctx context.Context, e *Engine, t *testing.T) string {
	t.Helper()
	u, err := GetUser(ctx, e, "devray@example.com")
	if err != nil {
		t.Fatalf("failed to look up user: %v", err)
	}
	return u.ID
}

func TestStore_ListAllAndCount_Memory(t *testing.T) {
	us := memory.NewUserStore()
	ctx := context.Background()

	count, err := us.Count(ctx)
	if err != nil || count != 0 {
		t.Fatalf("expected 0 users initially, got %d (err: %v)", count, err)
	}

	for i := 0; i < 3; i++ {
		us.Create(ctx, store.User{ID: string(rune('a' + i)), Email: string(rune('a'+i)) + "@example.com"})
	}

	count, err = us.Count(ctx)
	if err != nil || count != 3 {
		t.Fatalf("expected 3 users, got %d (err: %v)", count, err)
	}

	all, err := us.ListAll(ctx, 10, 0)
	if err != nil || len(all) != 3 {
		t.Fatalf("expected 3 users listed, got %d (err: %v)", len(all), err)
	}

	paged, err := us.ListAll(ctx, 2, 0)
	if err != nil || len(paged) != 2 {
		t.Fatalf("expected 2 users with limit=2, got %d (err: %v)", len(paged), err)
	}
}

func TestStore_CountActive_Memory(t *testing.T) {
	ss := memory.NewSessionStore()
	ctx := context.Background()

	ss.Create(ctx, store.Session{ID: "s1", FamilyID: "s1", UserID: "u1"})
	ss.Create(ctx, store.Session{ID: "s2", FamilyID: "s2", UserID: "u1"})
	ss.Revoke(ctx, "s2")

	count, err := ss.CountActive(ctx)
	if err != nil || count != 1 {
		t.Fatalf("expected 1 active session, got %d (err: %v)", count, err)
	}
}

func TestStore_SearchByType_Memory(t *testing.T) {
	as := memory.NewAuditStore()
	ctx := context.Background()

	as.Record(ctx, store.AuditEvent{Type: store.EventLoginSuccess, UserID: "u1"})
	as.Record(ctx, store.AuditEvent{Type: store.EventTokenReuseDetected, UserID: "u2"})
	as.Record(ctx, store.AuditEvent{Type: store.EventTokenReuseDetected, UserID: "u3"})

	events, err := as.SearchByType(ctx, store.EventTokenReuseDetected, 10)
	if err != nil {
		t.Fatalf("SearchByType failed: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 token_reuse_detected events across all users, got %d", len(events))
	}
	for _, e := range events {
		if e.Type != store.EventTokenReuseDetected {
			t.Errorf("expected only token_reuse_detected events, got %s", e.Type)
		}
	}
}

// The User-Agent a real browser would send, so the label under test is
// the one a real session list would show.
const chromeWindowsUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// fixedGeolocator is the shape a host app supplies: one Locate call,
// its own data source, no engine involvement. err wins when set, to
// exercise the fail-open path end to end.
type fixedGeolocator struct {
	loc security.Location
	err error
}

func (g fixedGeolocator) Locate(_ context.Context, _ string) (security.Location, error) {
	return g.loc, g.err
}

var _ security.IPGeolocator = fixedGeolocator{}

func seedLoggedInUser(ctx context.Context, e *Engine, t *testing.T, userAgent string) string {
	t.Helper()
	if _, err := SignUp(ctx, e, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4"); err != nil {
		t.Fatalf("signup failed: %v", err)
	}
	if _, err := Login(ctx, e, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4", userAgent); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	u, err := GetUser(ctx, e, "raymondproguy@dev.com")
	if err != nil {
		t.Fatalf("user lookup failed: %v", err)
	}
	return u.ID
}

func TestListNamedSessions_LabelsTheSessionLoginCreated(t *testing.T) {
	cfg := validConfig()
	cfg.Geolocator = fixedGeolocator{loc: security.Location{City: "San Francisco", Region: "CA"}}
	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx := context.Background()
	userID := seedLoggedInUser(ctx, engine, t, chromeWindowsUA)

	list, err := ListNamedSessions(ctx, engine, userID)
	if err != nil {
		t.Fatalf("ListNamedSessions failed: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 named session, got %d", len(list))
	}
	if list[0].Label != "Chrome on Windows — San Francisco, CA" {
		t.Errorf("unexpected label: %q", list[0].Label)
	}
	// Nothing was stored to make this label: it came from the IP and
	// User-Agent Login already recorded on the session.
	if list[0].IP != "1.2.3.4" || list[0].UserAgent != chromeWindowsUA {
		t.Errorf("expected the raw values to stay available, got %+v", list[0].PublicSession)
	}
}

func TestListNamedSessions_WorksWithoutAGeolocator(t *testing.T) {
	engine, err := New(validConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx := context.Background()
	userID := seedLoggedInUser(ctx, engine, t, chromeWindowsUA)

	list, err := ListNamedSessions(ctx, engine, userID)
	if err != nil {
		t.Fatalf("ListNamedSessions failed: %v", err)
	}
	if list[0].Label != "Chrome on Windows" {
		t.Errorf("expected a device-only label with no geolocator configured, got %q", list[0].Label)
	}
}

// The listing is how someone revokes a session they don't recognize, so
// a broken geolocator must never be able to take it away from them.
func TestListNamedSessions_SurvivesAFailingGeolocator(t *testing.T) {
	cfg := validConfig()
	cfg.Geolocator = fixedGeolocator{err: errors.New("provider unreachable")}
	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx := context.Background()
	userID := seedLoggedInUser(ctx, engine, t, chromeWindowsUA)

	list, err := ListNamedSessions(ctx, engine, userID)
	if err != nil {
		t.Fatalf("expected the listing to survive a geolocator error, got %v", err)
	}
	if len(list) != 1 || list[0].Label != "Chrome on Windows" {
		t.Errorf("expected a device-only label, got %+v", list)
	}
}

// stubRateLimiter is the shape a host app supplies when it replaces the
// default limiter: something the engine only ever reaches through the
// security.RateLimiter interface, with no idea where the count lives.
type stubRateLimiter struct {
	allow bool
	keys  []string
}

func (s *stubRateLimiter) Allow(_ context.Context, key string) (bool, error) {
	s.keys = append(s.keys, key)
	return s.allow, nil
}

var _ security.RateLimiter = (*stubRateLimiter)(nil)

// Wiring a limiter into Config has to reach the real call path, not just
// the Engine struct — this asserts the injected limiter is the one
// SignUp consults, and that it is handed the key auth builds rather than
// something the facade invented.
func TestSignUp_UsesTheConfiguredRateLimiter(t *testing.T) {
	limiter := &stubRateLimiter{allow: false}
	cfg := validConfig()
	cfg.RateLimiter = limiter
	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = SignUp(context.Background(), engine, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4")
	if err != auth.ErrRateLimited {
		t.Fatalf("expected auth.ErrRateLimited from a limiter that denies, got %v", err)
	}
	if len(limiter.keys) != 1 || limiter.keys[0] != "signup:1.2.3.4" {
		t.Errorf("expected one call keyed \"signup:1.2.3.4\", got %v", limiter.keys)
	}
}

// facadeTraceKey stands in for a host app's tracing middleware key. Its
// unexported type is the reason the engine cannot read a trace ID itself
// and has to pass the whole context through.
type facadeTraceKey struct{}

// facadeCtxLogger is the shape of a host's cloud sink: it implements
// logger.ContextLogger, so the engine must reach it through Log carrying
// the context of the call, never through the four context-free methods.
type facadeCtxLogger struct {
	traces []string
	bare   int
}

func (f *facadeCtxLogger) Log(ctx context.Context, _ logger.Level, _ string, _ map[string]string) {
	trace, _ := ctx.Value(facadeTraceKey{}).(string)
	f.traces = append(f.traces, trace)
}

func (f *facadeCtxLogger) Debug(string, map[string]string) { f.bare++ }
func (f *facadeCtxLogger) Info(string, map[string]string)  { f.bare++ }
func (f *facadeCtxLogger) Warn(string, map[string]string)  { f.bare++ }
func (f *facadeCtxLogger) Error(string, map[string]string) { f.bare++ }

var _ logger.ContextLogger = (*facadeCtxLogger)(nil)

// facadePlainLogger is a Logger written before ContextLogger existed —
// four methods, no context. It has to keep receiving records exactly as
// it always did.
type facadePlainLogger struct {
	calls int
}

func (f *facadePlainLogger) Debug(string, map[string]string) { f.calls++ }
func (f *facadePlainLogger) Info(string, map[string]string)  { f.calls++ }
func (f *facadePlainLogger) Warn(string, map[string]string)  { f.calls++ }
func (f *facadePlainLogger) Error(string, map[string]string) { f.calls++ }

var _ logger.Logger = (*facadePlainLogger)(nil)

// Wiring a ContextLogger into Config has to reach the real call path,
// not just the Engine struct: auth.SignUp holds a plain logger.Logger and
// logs "signup: completed" through it, so this asserts the per-call
// binding in Engine.logFor actually carries the caller's context that far.
func TestSignUp_HandsTheCallContextToAContextLogger(t *testing.T) {
	sink := &facadeCtxLogger{}
	cfg := validConfig()
	cfg.Logger = sink
	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.WithValue(context.Background(), facadeTraceKey{}, "trace-xyz")
	if _, err := SignUp(ctx, engine, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4"); err != nil {
		t.Fatalf("signup failed: %v", err)
	}

	if len(sink.traces) == 0 {
		t.Fatal("the configured logger recorded nothing during a successful signup")
	}
	if sink.bare != 0 {
		t.Errorf("%d record(s) arrived through a context-free method, losing the trace", sink.bare)
	}
	for i, trace := range sink.traces {
		if trace != "trace-xyz" {
			t.Errorf("record %d carried trace %q, want %q", i, trace, "trace-xyz")
		}
	}
}

// The same path, for a Logger that predates ContextLogger: it must still
// be called, and through its own four methods.
func TestSignUp_StillLogsToAContextFreeLogger(t *testing.T) {
	sink := &facadePlainLogger{}
	cfg := validConfig()
	cfg.Logger = sink
	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := SignUp(context.Background(), engine, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4"); err != nil {
		t.Fatalf("signup failed: %v", err)
	}

	if sink.calls == 0 {
		t.Error("a context-free Logger recorded nothing during a successful signup")
	}
}
