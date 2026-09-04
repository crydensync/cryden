package auth

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
)

// stuffingTestThresholds keeps the breadth threshold small so a test can
// spray five accounts instead of ten, and leaves Cooldown at zero so
// every crossing is visible — suppression gets its own test below.
var stuffingTestThresholds = security.CredentialStuffingThresholds{
	Window:         15 * time.Minute,
	TargetAccounts: 5,
}

// seedVictim creates one more account for a spray to aim at, alongside
// the standard placeholder identity seedUser creates.
func (d *anomalyDeps) seedVictim(ctx context.Context, t *testing.T, id, email string) {
	t.Helper()
	hash, err := d.hasher.Hash("Tr0ubl3-Fr33!2026")
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}
	if err := d.users.Create(ctx, storeUser(id, email, hash)); err != nil {
		t.Fatalf("seeding %s failed: %v", email, err)
	}
}

// loginAs is d.login for an arbitrary email and stuffing configuration —
// a spray, by definition, cannot go through one account's helper.
func (d *anomalyDeps) loginAs(ctx context.Context, anomalies store.AnomalyStore, stuffing security.CredentialStuffingThresholds, email, password, ip string) (Tokens, error) {
	return Login(ctx, d.users, d.sessions, nil, nil, nil, anomalies,
		d.hasher, d.ids, d.refresh, d.jwt, nil, d.limiter, d.audit, d.log,
		email, password, ip, "test-agent", 100, time.Minute, anomalyTestThresholds, stuffing)
}

func stuffingEvents(t *testing.T, d *anomalyDeps) []store.AuditEvent {
	t.Helper()
	events, err := d.audit.SearchByType(context.Background(), store.EventCredentialStuffingDetected, 100)
	if err != nil {
		t.Fatalf("searching audit events failed: %v", err)
	}
	return events
}

// The gap this feature exists to close: one password tried against many
// accounts. Each account sees a single failure, so per-account lockout
// never fires and nothing in item 8's per-account signals notices.
func TestCredentialStuffing_SprayAcrossAccountsIsFlagged(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)

	for i := 1; i <= 5; i++ {
		email := "victim-" + strconv.Itoa(i) + "@dev.com"
		d.seedVictim(ctx, t, "victim-"+strconv.Itoa(i), email)
		if _, err := d.loginAs(ctx, d.anomalies, stuffingTestThresholds, email, "one-leaked-password", "6.6.6.6"); err != ErrInvalidCredentials {
			t.Fatalf("%s: expected ErrInvalidCredentials, got %v", email, err)
		}
	}

	events := stuffingEvents(t, d)
	if len(events) == 0 {
		t.Fatal("five distinct accounts from one address should have been flagged")
	}
	last := events[0]
	if last.IP != "6.6.6.6" {
		t.Fatalf("expected the flagged IP on the event, got %q", last.IP)
	}
	if last.Metadata["signals"] != string(security.SignalAccountSpray) {
		t.Fatalf("expected account_spray alone for real accounts, got %q", last.Metadata["signals"])
	}
	if last.Metadata["distinct_accounts"] != "5" {
		t.Fatalf("expected 5 distinct accounts in the metadata, got %q", last.Metadata["distinct_accounts"])
	}
}

// The same spray aimed at a list of addresses that were never registered
// here. Those attempts carry no user ID at all, so they are only ever
// visible per-IP — and they are the bulk of a list bought elsewhere.
func TestCredentialStuffing_UnknownEmailSprayIsFlaggedAndQualified(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)

	for i := 1; i <= 5; i++ {
		email := "nobody-" + strconv.Itoa(i) + "@dev.com"
		if _, err := d.loginAs(ctx, d.anomalies, stuffingTestThresholds, email, "one-leaked-password", "6.6.6.6"); err != ErrInvalidCredentials {
			t.Fatalf("%s: expected ErrInvalidCredentials, got %v", email, err)
		}
	}

	events := stuffingEvents(t, d)
	if len(events) == 0 {
		t.Fatal("a spray against unknown addresses should have been flagged")
	}
	last := events[0]
	if last.Metadata["signals"] != "account_spray,unknown_account_spray" {
		t.Fatalf("expected the unknown-heavy qualifier, got %q", last.Metadata["signals"])
	}
	if last.Metadata["unknown_targets"] != "5" || last.Metadata["distinct_accounts"] != "0" {
		t.Fatalf("unexpected breadth metadata: %+v", last.Metadata)
	}
	// The event is about the IP, and no account owns it.
	if last.UserID != "" {
		t.Fatalf("an unknown-email spray has no user to attribute to, got %q", last.UserID)
	}
}

// The case that is NOT credential stuffing, and the reason breadth is
// counted in distinct targets rather than attempts: one account
// hammered repeatedly is what LockoutThreshold and item 8's per-account
// velocity signal already cover.
func TestCredentialStuffing_HammeringOneAccountIsNotASpray(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	d.seedUser(ctx, t)

	for i := 0; i < 12; i++ {
		if _, err := d.loginAs(ctx, d.anomalies, stuffingTestThresholds, "raymondproguy@dev.com", "wrong-password", "6.6.6.6"); err != ErrInvalidCredentials {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i, err)
		}
	}

	if events := stuffingEvents(t, d); len(events) != 0 {
		t.Fatalf("twelve failures against one account is not a spray, got %v", events)
	}
}

// The most valuable case in the feature: a login that SUCCEEDS from an
// address currently spraying means one of the guesses landed.
func TestCredentialStuffing_SuccessFromASprayingIPIsFlagged(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	d.seedUser(ctx, t)

	for i := 1; i <= 5; i++ {
		email := "nobody-" + strconv.Itoa(i) + "@dev.com"
		if _, err := d.loginAs(ctx, d.anomalies, stuffingTestThresholds, email, "one-leaked-password", "6.6.6.6"); err != ErrInvalidCredentials {
			t.Fatalf("%s: expected ErrInvalidCredentials, got %v", email, err)
		}
	}

	tokens, err := d.loginAs(ctx, d.anomalies, stuffingTestThresholds, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "6.6.6.6")
	if err != nil {
		t.Fatalf("detection must never block a valid login: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("expected tokens to be issued")
	}

	// With Cooldown at zero the success records its own event, and that
	// event names the account that got in.
	var found bool
	for _, e := range stuffingEvents(t, d) {
		if e.UserID == "user-1" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected the successful login from the spraying address to be flagged against its account")
	}
}

// Without suppression a sustained spray emits one audit event per failed
// attempt — thousands of identical records describing one incident.
func TestCredentialStuffing_CooldownSuppressesRepeats(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)

	thresholds := stuffingTestThresholds
	thresholds.Cooldown = time.Hour

	for i := 1; i <= 12; i++ {
		email := "nobody-" + strconv.Itoa(i) + "@dev.com"
		if _, err := d.loginAs(ctx, d.anomalies, thresholds, email, "one-leaked-password", "6.6.6.6"); err != ErrInvalidCredentials {
			t.Fatalf("%s: expected ErrInvalidCredentials, got %v", email, err)
		}
	}

	if events := stuffingEvents(t, d); len(events) != 1 {
		t.Fatalf("expected the cooldown to collapse eight crossings into one event, got %d", len(events))
	}
}

// A second address spraying at the same time is its own incident and
// must not be silenced by the first one's cooldown.
func TestCredentialStuffing_CooldownIsPerIP(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)

	thresholds := stuffingTestThresholds
	thresholds.Cooldown = time.Hour

	for _, ip := range []string{"6.6.6.6", "7.7.7.7"} {
		for i := 1; i <= 6; i++ {
			email := "nobody-" + ip + "-" + strconv.Itoa(i) + "@dev.com"
			if _, err := d.loginAs(ctx, d.anomalies, thresholds, email, "one-leaked-password", ip); err != ErrInvalidCredentials {
				t.Fatalf("%s: expected ErrInvalidCredentials, got %v", email, err)
			}
		}
	}

	events := stuffingEvents(t, d)
	if len(events) != 2 {
		t.Fatalf("expected one event per spraying address, got %d", len(events))
	}
	if events[0].IP == events[1].IP {
		t.Fatalf("expected two different addresses, got %q twice", events[0].IP)
	}
}

// Config.Anomalies is the single on/off switch for both features, so a
// host app that never configured it gets no detection of either kind and
// nothing about login changes.
func TestCredentialStuffing_OffWithoutAnAnomalyStore(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	d.seedUser(ctx, t)

	for i := 1; i <= 8; i++ {
		email := "nobody-" + strconv.Itoa(i) + "@dev.com"
		if _, err := d.loginAs(ctx, nil, security.DefaultCredentialStuffingThresholds, email, "one-leaked-password", "6.6.6.6"); err != ErrInvalidCredentials {
			t.Fatalf("%s: expected ErrInvalidCredentials, got %v", email, err)
		}
	}
	if _, err := d.loginAs(ctx, nil, security.DefaultCredentialStuffingThresholds, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "6.6.6.6"); err != nil {
		t.Fatalf("login must be unaffected with detection unconfigured: %v", err)
	}

	if events := stuffingEvents(t, d); len(events) != 0 {
		t.Fatalf("no anomaly store means no detection at all, got %d events", len(events))
	}
}

// The per-feature off switch: a zero TargetAccounts silences credential
// stuffing while leaving item 8's per-account detection running. The two
// threshold structs are separate precisely so this is possible.
func TestCredentialStuffing_ZeroTargetAccountsSilencesOnlyThisFeature(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	user := d.seedUser(ctx, t)

	for i := 1; i <= 8; i++ {
		email := "nobody-" + strconv.Itoa(i) + "@dev.com"
		if _, err := d.loginAs(ctx, d.anomalies, noStuffingThresholds, email, "one-leaked-password", "6.6.6.6"); err != ErrInvalidCredentials {
			t.Fatalf("%s: expected ErrInvalidCredentials, got %v", email, err)
		}
	}
	if _, err := d.loginAs(ctx, d.anomalies, noStuffingThresholds, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "6.6.6.6"); err != nil {
		t.Fatalf("login should succeed: %v", err)
	}

	if events := stuffingEvents(t, d); len(events) != 0 {
		t.Fatalf("a zero TargetAccounts must silence this feature, got %d events", len(events))
	}
	if events := countEvents(t, d.audit, user.ID, store.EventAnomalyDetected); len(events) == 0 {
		t.Fatal("silencing credential stuffing must not disable anomaly detection")
	}
}

// Detection reads storage on the hot path of every login, so a broken
// store has to degrade to "no detection," never to "no logins."
func TestCredentialStuffing_StorageFailureNeverBlocksLogin(t *testing.T) {
	ctx := context.Background()
	d := newAnomalyDeps(t)
	d.seedUser(ctx, t)

	broken := failingAnomalyStore{}
	for i := 1; i <= 8; i++ {
		email := "nobody-" + strconv.Itoa(i) + "@dev.com"
		if _, err := d.loginAs(ctx, broken, stuffingTestThresholds, email, "one-leaked-password", "6.6.6.6"); err != ErrInvalidCredentials {
			t.Fatalf("%s: expected ErrInvalidCredentials, got %v", email, err)
		}
	}

	tokens, err := d.loginAs(ctx, broken, stuffingTestThresholds, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "6.6.6.6")
	if err != nil {
		t.Fatalf("a broken anomaly store must not fail a valid login: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("expected tokens to be issued")
	}
	if events := stuffingEvents(t, d); len(events) != 0 {
		t.Fatalf("a store that cannot be read has nothing to flag, got %d events", len(events))
	}
}
