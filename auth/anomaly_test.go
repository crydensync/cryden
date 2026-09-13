package auth

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"
)

// anomalyTestThresholds keeps the numbers small so a test can reach a
// velocity threshold in a few calls instead of twenty.
var anomalyTestThresholds = security.AnomalyThresholds{
	Window:                15 * time.Minute,
	HistorySize:           20,
	UserFailureVelocity:   3,
	IPFailureVelocity:     5,
	MaxConcurrentSessions: 50,
	TokenReuseLookback:    24 * time.Hour,
}

type anomalyDeps struct {
	users     *memory.UserStore
	sessions  *memory.SessionStore
	audit     *memory.AuditStore
	anomalies *memory.AnomalyStore
	hasher    security.Hasher
	ids       security.IDGenerator
	refresh   token.TokenGenerator
	jwt       *token.JWTIssuer
	limiter   security.RateLimiter
	log       testLogger
}

func newAnomalyDeps(t *testing.T) *anomalyDeps {
	t.Helper()
	hasher, _ := security.NewBcryptHasher(4)
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	return &anomalyDeps{
		users:     memory.NewUserStore(),
		sessions:  memory.NewSessionStore(),
		audit:     memory.NewAuditStore(),
		anomalies: memory.NewAnomalyStore(),
		hasher:    hasher,
		ids:       security.NewUUIDv7Generator(),
		refresh:   refreshGen,
		jwt:       jwtIssuer,
		limiter:   security.NewInMemoryRateLimiter(1000, time.Minute),
		log:       testLogger{},
	}
}

// seedUser creates the standard placeholder identity.
func (d *anomalyDeps) seedUser(ctx context.Context, t *testing.T) store.User {
	t.Helper()
	hash, err := d.hasher.Hash("Tr0ubl3-Fr33!2026")
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}
	u := storeUser("user-1", "raymondproguy@dev.com", hash)
	if err := d.users.Create(ctx, u); err != nil {
		t.Fatalf("seeding the user failed: %v", err)
	}
	return u
}

// login runs a password login through the real Login path, with the
// anomaly store wired in unless anomalies is explicitly nil.
func (d *anomalyDeps) login(ctx context.Context, anomalies store.AnomalyStore, password, ip, agent string) (Tokens, error) {
	return d.loginWith(ctx, anomalies, anomalyTestThresholds, password, ip, agent)
}

func (d *anomalyDeps) loginWith(ctx context.Context, anomalies store.AnomalyStore, thresholds security.AnomalyThresholds, password, ip, agent string) (Tokens, error) {
	return Login(ctx, d.users, d.sessions, nil, nil, nil, anomalies,
		d.hasher, d.ids, d.refresh, d.jwt, nil, d.limiter, d.audit, d.log,
		"raymondproguy@dev.com", password, ip, agent, 100, time.Minute, thresholds)
}

func countEvents(t *testing.T, audit *memory.AuditStore, userID string, typ store.AuditEventType) []store.AuditEvent {
	t.Helper()
	events, err := audit.ListByUser(context.Background(), userID, 100)
	if err != nil {
		t.Fatalf("listing audit events failed: %v", err)
	}
	var out []store.AuditEvent
	for _, e := range events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// The feature is off until a store is injected, exactly like TOTP and
// recovery codes. A nil AnomalyStore must change nothing at all.
func TestDetectLoginAnomalies_NilStoreIsANoOp(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	d.seedUser(ctx, t)

	if _, err := d.login(ctx, nil, "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent"); err != nil {
		t.Fatalf("login with detection off failed: %v", err)
	}
	if _, err := d.login(ctx, nil, "wrong-password", "1.2.3.4", "test-agent"); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	if events := countEvents(t, d.audit, "user-1", store.EventAnomalyDetected); len(events) != 0 {
		t.Fatalf("detection off must record no anomaly events, got %d", len(events))
	}
}

// A first login has no baseline, so it must be clean — and it must still
// be recorded, because it is the baseline for the next one.
func TestDetectLoginAnomalies_FirstLoginIsCleanButRecorded(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	d.seedUser(ctx, t)

	if _, err := d.login(ctx, d.anomalies, "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent"); err != nil {
		t.Fatalf("first login failed: %v", err)
	}

	if events := countEvents(t, d.audit, "user-1", store.EventAnomalyDetected); len(events) != 0 {
		t.Fatalf("a first-ever login should not be flagged, got %v", events)
	}

	recent, err := d.anomalies.ListRecentSuccesses(ctx, "user-1", 20)
	if err != nil {
		t.Fatalf("ListRecentSuccesses failed: %v", err)
	}
	if len(recent) != 1 {
		t.Fatalf("expected the successful attempt to be recorded, got %d", len(recent))
	}
	if recent[0].IP != "1.2.3.4" || recent[0].UserAgent != "test-agent" {
		t.Fatalf("recorded attempt lost its context: %+v", recent[0])
	}
}

// Second login from a different address and browser: both signals, on
// an otherwise entirely successful authentication.
func TestDetectLoginAnomalies_NewIPAndDeviceFlagWithoutBlocking(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	d.seedUser(ctx, t)

	if _, err := d.login(ctx, d.anomalies, "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent"); err != nil {
		t.Fatalf("baseline login failed: %v", err)
	}

	tokens, err := d.login(ctx, d.anomalies, "Tr0ubl3-Fr33!2026", "9.9.9.9", "other-agent")
	if err != nil {
		t.Fatalf("a flagged login must still succeed, got %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("a flagged login must still issue tokens")
	}

	events := countEvents(t, d.audit, "user-1", store.EventAnomalyDetected)
	if len(events) != 1 {
		t.Fatalf("expected exactly 1 anomaly event, got %d", len(events))
	}
	if got := events[0].Metadata["signals"]; got != "new_ip,new_device" {
		t.Fatalf("signals = %q, want %q", got, "new_ip,new_device")
	}
	if events[0].IP != "9.9.9.9" {
		t.Fatalf("the event should carry the attempt's IP, got %q", events[0].IP)
	}
}

// A returning user on their known address and browser stays quiet. This
// is the case that decides whether the feature is usable at all: if a
// routine login flags, every login flags.
func TestDetectLoginAnomalies_FamiliarLoginStaysQuiet(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	d.seedUser(ctx, t)

	for i := 0; i < 4; i++ {
		if _, err := d.login(ctx, d.anomalies, "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent"); err != nil {
			t.Fatalf("login %d failed: %v", i, err)
		}
	}

	if events := countEvents(t, d.audit, "user-1", store.EventAnomalyDetected); len(events) != 0 {
		t.Fatalf("repeat logins from a known IP and device must stay quiet, got %v", events)
	}
}

// Wrong-password attempts feed the velocity counts — that is the only
// reason the failure path records anything.
func TestDetectLoginAnomalies_FailuresFeedUserVelocity(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	d.seedUser(ctx, t)

	// Baseline first, so the eventual success is judged against a known
	// IP and device and only the velocity signal can fire.
	if _, err := d.login(ctx, d.anomalies, "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent"); err != nil {
		t.Fatalf("baseline login failed: %v", err)
	}

	for i := 0; i < anomalyTestThresholds.UserFailureVelocity; i++ {
		if _, err := d.login(ctx, d.anomalies, "wrong-password", "1.2.3.4", "test-agent"); err != ErrInvalidCredentials {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i, err)
		}
	}

	count, err := d.anomalies.CountFailuresForUser(ctx, "user-1", time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatalf("CountFailuresForUser failed: %v", err)
	}
	if count != anomalyTestThresholds.UserFailureVelocity {
		t.Fatalf("expected %d recorded failures, got %d", anomalyTestThresholds.UserFailureVelocity, count)
	}

	// The password is right this time; the burst that preceded it is
	// what gets surfaced.
	if _, err := d.login(ctx, d.anomalies, "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent"); err != nil {
		t.Fatalf("the recovering login must still succeed: %v", err)
	}

	events := countEvents(t, d.audit, "user-1", store.EventAnomalyDetected)
	if len(events) != 1 {
		t.Fatalf("expected 1 anomaly event, got %d", len(events))
	}
	if got := events[0].Metadata["signals"]; got != "user_failure_velocity" {
		t.Fatalf("signals = %q, want %q", got, "user_failure_velocity")
	}
	want := strconv.Itoa(anomalyTestThresholds.UserFailureVelocity)
	if got := events[0].Metadata["user_failures"]; got != want {
		t.Fatalf("user_failures = %q, want %q", got, want)
	}
}

// The per-IP count spans every account an address touched, including
// attempts against emails that resolve to no account at all — which is
// the shape of a spray, and the reason this signal is separate from the
// per-user one.
func TestDetectLoginAnomalies_FailuresFromOneIPCountAcrossAccounts(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	d.seedUser(ctx, t)

	if _, err := d.login(ctx, d.anomalies, "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent"); err != nil {
		t.Fatalf("baseline login failed: %v", err)
	}

	// Attempts against addresses with no account behind them. These
	// carry no user ID, so they can only be counted per-IP.
	for i := 0; i < 5; i++ {
		_, err := Login(ctx, d.users, d.sessions, nil, nil, nil, d.anomalies,
			d.hasher, d.ids, d.refresh, d.jwt, nil, d.limiter, d.audit, d.log,
			"nobody@dev.com", "guess", "1.2.3.4", "test-agent", 100, time.Minute, anomalyTestThresholds)
		if err != ErrInvalidCredentials {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i, err)
		}
	}

	since := time.Now().Add(-time.Minute)
	if n, _ := d.anomalies.CountFailuresForIP(ctx, "1.2.3.4", since); n != 5 {
		t.Fatalf("expected 5 failures from the IP, got %d", n)
	}
	// None of them are attributable to the real account.
	if n, _ := d.anomalies.CountFailuresForUser(ctx, "user-1", since); n != 0 {
		t.Fatalf("unknown-email failures must not attach to a real user, got %d", n)
	}

	if _, err := d.login(ctx, d.anomalies, "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent"); err != nil {
		t.Fatalf("the legitimate login must still succeed: %v", err)
	}

	events := countEvents(t, d.audit, "user-1", store.EventAnomalyDetected)
	if len(events) != 1 {
		t.Fatalf("expected 1 anomaly event, got %d", len(events))
	}
	if got := events[0].Metadata["signals"]; got != "ip_failure_velocity" {
		t.Fatalf("signals = %q, want %q", got, "ip_failure_velocity")
	}
	if got := events[0].Metadata["ip_failures"]; got != "5" {
		t.Fatalf("ip_failures = %q, want %q", got, "5")
	}
}

func TestDetectLoginAnomalies_ConcurrentSessionsFlagged(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	d.seedUser(ctx, t)

	thresholds := anomalyTestThresholds
	thresholds.MaxConcurrentSessions = 2

	// Observations are read before this attempt's own session exists, so
	// login N sees N-1 active sessions. Four logins is the first point
	// where the count observed (3) exceeds a limit of 2.
	for i := 0; i < 4; i++ {
		if _, err := d.loginWith(ctx, d.anomalies, thresholds, "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent"); err != nil {
			t.Fatalf("login %d failed: %v", i, err)
		}
	}

	events := countEvents(t, d.audit, "user-1", store.EventAnomalyDetected)
	if len(events) != 1 {
		t.Fatalf("expected the fourth login to be the only one flagged, got %d", len(events))
	}
	if got := events[0].Metadata["signals"]; got != "concurrent_sessions" {
		t.Fatalf("signals = %q, want %q", got, "concurrent_sessions")
	}
	if got := events[0].Metadata["active_sessions"]; got != "3" {
		t.Fatalf("active_sessions = %q, want %q", got, "3")
	}
}

// Refresh-token reuse already revokes the family when it happens. This
// signal makes a login arriving afterward visibly connected to it.
func TestDetectLoginAnomalies_TokenReuseHistoryFlagsLaterLogin(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	d.seedUser(ctx, t)

	if _, err := d.login(ctx, d.anomalies, "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent"); err != nil {
		t.Fatalf("baseline login failed: %v", err)
	}
	if err := d.audit.Record(ctx, store.AuditEvent{
		Type:   store.EventTokenReuseDetected,
		UserID: "user-1",
		IP:     "9.9.9.9",
	}); err != nil {
		t.Fatalf("seeding the reuse event failed: %v", err)
	}

	if _, err := d.login(ctx, d.anomalies, "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent"); err != nil {
		t.Fatalf("login after a reuse event must still succeed: %v", err)
	}

	events := countEvents(t, d.audit, "user-1", store.EventAnomalyDetected)
	if len(events) != 1 {
		t.Fatalf("expected 1 anomaly event, got %d", len(events))
	}
	if got := events[0].Metadata["signals"]; got != "token_reuse" {
		t.Fatalf("signals = %q, want %q", got, "token_reuse")
	}
	if got := events[0].Metadata["token_reuse_events"]; got != "1" {
		t.Fatalf("token_reuse_events = %q, want %q", got, "1")
	}
}

// A reuse event older than TokenReuseLookback must stop counting, or one
// incident flags every login the account ever makes again.
func TestDetectLoginAnomalies_TokenReuseLookbackExpires(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	d.seedUser(ctx, t)

	if _, err := d.login(ctx, d.anomalies, "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent"); err != nil {
		t.Fatalf("baseline login failed: %v", err)
	}
	_ = d.audit.Record(ctx, store.AuditEvent{Type: store.EventTokenReuseDetected, UserID: "user-1"})

	thresholds := anomalyTestThresholds
	// A lookback this short means the event just recorded is already
	// outside it.
	thresholds.TokenReuseLookback = time.Nanosecond

	if _, err := d.loginWith(ctx, d.anomalies, thresholds, "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent"); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if events := countEvents(t, d.audit, "user-1", store.EventAnomalyDetected); len(events) != 0 {
		t.Fatalf("an expired reuse event must not flag, got %v", events)
	}
}

// Ordering guarantee: if the current attempt were recorded before its
// own observations were gathered, its IP would already look familiar and
// new_ip could never fire. This is that invariant, stated directly.
func TestDetectLoginAnomalies_AttemptIsNotInItsOwnBaseline(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	d.seedUser(ctx, t)

	if _, err := d.login(ctx, d.anomalies, "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent"); err != nil {
		t.Fatalf("baseline login failed: %v", err)
	}
	// Same device, new address: new_ip must fire even though this very
	// attempt is about to be added to the history from that address.
	if _, err := d.login(ctx, d.anomalies, "Tr0ubl3-Fr33!2026", "9.9.9.9", "test-agent"); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	events := countEvents(t, d.audit, "user-1", store.EventAnomalyDetected)
	if len(events) != 1 || events[0].Metadata["signals"] != "new_ip" {
		t.Fatalf("expected exactly one new_ip event, got %v", events)
	}

	// And now that it is in the history, the same address is familiar.
	if _, err := d.login(ctx, d.anomalies, "Tr0ubl3-Fr33!2026", "9.9.9.9", "test-agent"); err != nil {
		t.Fatalf("repeat login failed: %v", err)
	}
	if events := countEvents(t, d.audit, "user-1", store.EventAnomalyDetected); len(events) != 1 {
		t.Fatalf("the now-known address must not flag again, got %d events", len(events))
	}
}

// Detection lives in completePrimaryAuth, the one tail every primary
// auth path reaches, so OAuth is covered by the same code as password
// login rather than by a second copy of it.
func TestDetectLoginAnomalies_CoversOAuthPath(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	oauth := memory.NewOAuthStore()

	loginOAuth := func(ip, agent string) {
		t.Helper()
		if _, err := LoginWithOAuth(ctx, d.users, oauth, d.sessions, nil, nil, nil, d.anomalies,
			d.ids, d.refresh, d.jwt, nil, d.audit, d.log,
			"google", "google-ext-id-1", "raymondproguy@dev.com", ip, agent, anomalyTestThresholds); err != nil {
			t.Fatalf("OAuth login from %s failed: %v", ip, err)
		}
	}

	loginOAuth("1.2.3.4", "test-agent")
	user, err := d.users.GetByEmail(ctx, "raymondproguy@dev.com")
	if err != nil {
		t.Fatalf("expected the OAuth login to create a user: %v", err)
	}
	if events := countEvents(t, d.audit, user.ID, store.EventAnomalyDetected); len(events) != 0 {
		t.Fatalf("a first OAuth login should not be flagged, got %v", events)
	}

	loginOAuth("9.9.9.9", "other-agent")
	events := countEvents(t, d.audit, user.ID, store.EventAnomalyDetected)
	if len(events) != 1 {
		t.Fatalf("expected the second OAuth login to be flagged, got %d", len(events))
	}
	if got := events[0].Metadata["signals"]; got != "new_ip,new_device" {
		t.Fatalf("signals = %q, want %q", got, "new_ip,new_device")
	}
}

func TestDetectLoginAnomalies_CoversMagicLinkPath(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	d.seedUser(ctx, t)
	verifications := memory.NewVerificationStore()
	tokenGen, _ := token.NewCryptoRandTokenGenerator(32)
	sender := &captureMagicLinkSender{}

	completeMagicLink := func(ip, agent string) {
		t.Helper()
		if err := RequestMagicLink(ctx, d.users, verifications, sender, tokenGen, d.ids, d.limiter, d.audit, d.log,
			"raymondproguy@dev.com", ip); err != nil {
			t.Fatalf("RequestMagicLink failed: %v", err)
		}
		if _, err := CompleteMagicLink(ctx, d.users, d.sessions, verifications, nil, nil, nil, d.anomalies,
			d.ids, d.refresh, d.jwt, nil, d.audit, d.log,
			sender.rawToken, ip, agent, anomalyTestThresholds); err != nil {
			t.Fatalf("CompleteMagicLink from %s failed: %v", ip, err)
		}
	}

	completeMagicLink("1.2.3.4", "test-agent")
	if events := countEvents(t, d.audit, "user-1", store.EventAnomalyDetected); len(events) != 0 {
		t.Fatalf("a first magic-link login should not be flagged, got %v", events)
	}

	completeMagicLink("9.9.9.9", "test-agent")
	events := countEvents(t, d.audit, "user-1", store.EventAnomalyDetected)
	if len(events) != 1 {
		t.Fatalf("expected the second magic-link login to be flagged, got %d", len(events))
	}
	if got := events[0].Metadata["signals"]; got != "new_ip" {
		t.Fatalf("signals = %q, want %q", got, "new_ip")
	}
}

// failingAnomalyStore fails every operation, standing in for a database
// that has gone away mid-request.
type failingAnomalyStore struct{}

func (failingAnomalyStore) RecordAttempt(ctx context.Context, attempt store.LoginAttempt) error {
	return errors.New("anomaly store unavailable")
}

func (failingAnomalyStore) ListRecentSuccesses(ctx context.Context, userID string, limit int) ([]store.LoginAttempt, error) {
	return nil, errors.New("anomaly store unavailable")
}

func (failingAnomalyStore) CountFailuresForUser(ctx context.Context, userID string, since time.Time) (int, error) {
	return 0, errors.New("anomaly store unavailable")
}

func (failingAnomalyStore) CountFailuresForIP(ctx context.Context, ip string, since time.Time) (int, error) {
	return 0, errors.New("anomaly store unavailable")
}

// A detector that can lock people out of their own accounts when its
// storage breaks is worse than no detector. Every read degrades to "no
// evidence" and the login proceeds.
func TestDetectLoginAnomalies_StorageFailureDoesNotBlockLogin(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	d.seedUser(ctx, t)

	tokens, err := d.login(ctx, failingAnomalyStore{}, "Tr0ubl3-Fr33!2026", "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("a broken anomaly store must not fail a valid login: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("expected tokens to be issued despite the storage failure")
	}

	// And a failed read must not be reported as "everything is
	// unfamiliar" — that would flag every login during an outage.
	if events := countEvents(t, d.audit, "user-1", store.EventAnomalyDetected); len(events) != 0 {
		t.Fatalf("a storage failure must not manufacture signals, got %v", events)
	}

	// Wrong credentials still fail for the ordinary reason.
	if _, err := d.login(ctx, failingAnomalyStore{}, "wrong-password", "1.2.3.4", "test-agent"); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

var _ store.AnomalyStore = failingAnomalyStore{}
