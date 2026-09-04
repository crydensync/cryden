package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"
	"golang.org/x/crypto/bcrypt"
)

// Small enough to keep the suite fast, and every field above the
// constructor's floor. Strength is not what these tests are about — which
// algorithm ends up in the users table is.
var rehashTestParams = security.Argon2idParams{
	Memory:      64,
	Iterations:  1,
	Parallelism: 1,
	SaltLength:  8,
	KeyLength:   16,
}

// loginDeps mirrors newLoginTestDeps but takes the hasher from the caller:
// every test here is about a hasher other than the default bcrypt one.
type loginDeps struct {
	users      store.UserStore
	sessions   *memory.SessionStore
	audit      *memory.AuditStore
	hasher     security.Hasher
	ids        security.IDGenerator
	refreshGen token.TokenGenerator
	jwtIssuer  *token.JWTIssuer
	limiter    security.RateLimiter
}

func newRehashDeps(t *testing.T, users store.UserStore, hasher security.Hasher) loginDeps {
	t.Helper()
	refreshGen, _ := token.NewCryptoRandTokenGenerator(32)
	jwtIssuer, _ := token.NewJWTIssuer("test-secret", time.Minute)
	return loginDeps{
		users:      users,
		sessions:   memory.NewSessionStore(),
		audit:      memory.NewAuditStore(),
		hasher:     hasher,
		ids:        security.NewUUIDv7Generator(),
		refreshGen: refreshGen,
		jwtIssuer:  jwtIssuer,
		limiter:    security.NewInMemoryRateLimiter(1000, time.Minute),
	}
}

func (d loginDeps) login(ctx context.Context, email, password string) (Tokens, error) {
	return Login(ctx, d.users, d.sessions, nil, nil, nil, nil, d.hasher, d.ids, d.refreshGen, d.jwtIssuer, nil,
		d.limiter, d.audit, testLogger{},
		email, password, "1.2.3.4", "test-agent", 5, time.Minute, noAnomalyThresholds, noStuffingThresholds)
}

func mustArgon2id(t *testing.T) *security.Argon2idHasher {
	t.Helper()
	h, err := security.NewArgon2idHasher(rehashTestParams)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return h
}

func storedHash(t *testing.T, users store.UserStore, id string) string {
	t.Helper()
	user, err := users.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return user.PasswordHash
}

func upgradeEvents(t *testing.T, audit *memory.AuditStore) []store.AuditEvent {
	t.Helper()
	events, err := audit.SearchByType(context.Background(), store.EventPasswordHashUpgraded, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return events
}

// The migration, end to end: a user whose password was hashed by bcrypt
// years ago logs in against an engine configured for Argon2id and comes
// out of it with an Argon2id hash — no password reset, no backfill job,
// nothing the user notices.
func TestLogin_UpgradesABcryptHashToArgon2id(t *testing.T) {
	ctx := context.Background()
	users := memory.NewUserStore()
	bcryptHasher, _ := security.NewBcryptHasher(4)
	oldHash, _ := bcryptHasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", oldHash))

	deps := newRehashDeps(t, users, security.NewMultiHasher(mustArgon2id(t)))

	if _, err := deps.login(ctx, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026"); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	newHash := storedHash(t, users, "user-1")
	if got := security.IdentifyHash(newHash); got != security.AlgorithmArgon2id {
		t.Fatalf("stored hash is %q, want argon2id", got)
	}

	events := upgradeEvents(t, deps.audit)
	if len(events) != 1 {
		t.Fatalf("got %d password_hash_upgraded events, want 1", len(events))
	}
	if events[0].UserID != "user-1" {
		t.Errorf("event user is %q, want user-1", events[0].UserID)
	}
	if events[0].Metadata["from"] != "bcrypt" || events[0].Metadata["to"] != "argon2id" {
		t.Errorf("event metadata is %v, want from=bcrypt to=argon2id", events[0].Metadata)
	}

	// The rewrite has to leave the account usable, which is the only part
	// of this a user would ever notice going wrong.
	if _, err := deps.login(ctx, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026"); err != nil {
		t.Errorf("second login after the upgrade failed: %v", err)
	}
	if len(upgradeEvents(t, deps.audit)) != 1 {
		t.Error("expected the second login to find the hash already current")
	}
}

// Raising bcrypt's cost is the same migration in miniature, and worth its
// own test because it is the case a host hits without changing algorithm
// at all.
func TestLogin_UpgradesABcryptHashToAHigherCost(t *testing.T) {
	ctx := context.Background()
	users := memory.NewUserStore()
	cheap, _ := security.NewBcryptHasher(4)
	oldHash, _ := cheap.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", oldHash))

	dearer, _ := security.NewBcryptHasher(6)
	deps := newRehashDeps(t, users, security.NewMultiHasher(dearer))

	if _, err := deps.login(ctx, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026"); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	newHash := storedHash(t, users, "user-1")
	if newHash == oldHash {
		t.Fatal("expected the hash to be rewritten at the new cost")
	}
	if cost, err := bcrypt.Cost([]byte(newHash)); err != nil || cost != 6 {
		t.Errorf("new hash has cost %d (err %v), want 6", cost, err)
	}
	if events := upgradeEvents(t, deps.audit); len(events) != 1 ||
		events[0].Metadata["from"] != "bcrypt" || events[0].Metadata["to"] != "bcrypt" {
		t.Errorf("got %v, want one bcrypt→bcrypt event", events)
	}
}

// A hash already written by the configured hasher is left exactly as it
// is: no pointless write, no audit noise on every single login.
func TestLogin_LeavesACurrentHashAlone(t *testing.T) {
	ctx := context.Background()
	users := memory.NewUserStore()
	hasher := security.NewMultiHasher(mustArgon2id(t))
	current, _ := hasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", current))

	deps := newRehashDeps(t, users, hasher)
	if _, err := deps.login(ctx, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026"); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if got := storedHash(t, users, "user-1"); got != current {
		t.Error("expected the stored hash to be untouched")
	}
	if events := upgradeEvents(t, deps.audit); len(events) != 0 {
		t.Errorf("got %d upgrade events, want none", len(events))
	}
}

// The upgrade hangs off a login that already succeeded, so a wrong
// password must never reach it — otherwise every failed guess would
// rewrite the victim's hash, which is a free denial-of-service worth of
// Argon2id work per attempt.
func TestLogin_DoesNotUpgradeOnAFailedLogin(t *testing.T) {
	ctx := context.Background()
	users := memory.NewUserStore()
	bcryptHasher, _ := security.NewBcryptHasher(4)
	oldHash, _ := bcryptHasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", oldHash))

	deps := newRehashDeps(t, users, security.NewMultiHasher(mustArgon2id(t)))
	if _, err := deps.login(ctx, "raymondproguy@dev.com", "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}

	if got := storedHash(t, users, "user-1"); got != oldHash {
		t.Error("a failed login rewrote the stored hash")
	}
	if events := upgradeEvents(t, deps.audit); len(events) != 0 {
		t.Errorf("got %d upgrade events, want none", len(events))
	}
}

// failingUpdateStore is a users table that accepts everything except the
// rewrite — a read-only replica, a permissions problem, a full disk.
type failingUpdateStore struct {
	*memory.UserStore
	err error
}

func (f failingUpdateStore) UpdatePasswordHash(context.Context, string, string) error {
	return f.err
}

// The upgrade is opportunistic. The user typed the right password, so
// they get their tokens; the hash stays out of date and the next login
// tries again.
func TestLogin_SucceedsWhenTheRehashCannotBeStored(t *testing.T) {
	ctx := context.Background()
	inner := memory.NewUserStore()
	bcryptHasher, _ := security.NewBcryptHasher(4)
	oldHash, _ := bcryptHasher.Hash("Tr0ubl3-Fr33!2026")
	inner.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", oldHash))
	users := failingUpdateStore{UserStore: inner, err: errors.New("read-only replica")}

	deps := newRehashDeps(t, users, security.NewMultiHasher(mustArgon2id(t)))
	tokens, err := deps.login(ctx, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026")
	if err != nil {
		t.Fatalf("expected the login to succeed anyway, got %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Error("expected both tokens to be populated")
	}

	if got := storedHash(t, inner, "user-1"); got != oldHash {
		t.Error("expected the stored hash to be unchanged")
	}
	// Nothing was upgraded, so nothing may claim it was — an operator
	// watching this event count is watching a migration drain.
	if events := upgradeEvents(t, deps.audit); len(events) != 0 {
		t.Errorf("got %d upgrade events, want none", len(events))
	}
}

// plainHasher implements security.Hasher and nothing more: a host's own
// implementation, written before Rehasher existed. It must keep working,
// and must never have its hashes rewritten on a guess about what it
// would have wanted.
type plainHasher struct{ inner security.Hasher }

func (p plainHasher) Hash(password string) (string, error) { return p.inner.Hash(password) }
func (p plainHasher) Compare(hash, password string) error  { return p.inner.Compare(hash, password) }

func TestLogin_NeverRehashesForAHasherThatCannotSay(t *testing.T) {
	ctx := context.Background()
	users := memory.NewUserStore()
	bcryptHasher, _ := security.NewBcryptHasher(4)
	oldHash, _ := bcryptHasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", oldHash))

	deps := newRehashDeps(t, users, plainHasher{inner: bcryptHasher})
	if _, err := deps.login(ctx, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026"); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if got := storedHash(t, users, "user-1"); got != oldHash {
		t.Error("expected no rewrite for a hasher that does not implement Rehasher")
	}
	if events := upgradeEvents(t, deps.audit); len(events) != 0 {
		t.Errorf("got %d upgrade events, want none", len(events))
	}
}

// Every second-factor and passwordless path reaches finishLogin without a
// plaintext password in hand, so the upgrade has to live on the password
// path alone. Asserted here so it is a decision on the record rather than
// something a later refactor moves into the shared tail by accident.
func TestLogin_UpgradeIsOnThePasswordPathOnly(t *testing.T) {
	ctx := context.Background()
	users := memory.NewUserStore()
	bcryptHasher, _ := security.NewBcryptHasher(4)
	oldHash, _ := bcryptHasher.Hash("Tr0ubl3-Fr33!2026")
	users.Create(ctx, storeUser("user-1", "raymondproguy@dev.com", oldHash))

	deps := newRehashDeps(t, users, security.NewMultiHasher(mustArgon2id(t)))
	user, _ := users.GetByID(ctx, "user-1")
	if _, err := finishLogin(ctx, deps.sessions, deps.ids, deps.refreshGen, deps.jwtIssuer, deps.audit,
		testLogger{}, user, "1.2.3.4", "test-agent", "", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := storedHash(t, users, "user-1"); got != oldHash {
		t.Error("expected a login with no plaintext password to leave the hash alone")
	}
}
