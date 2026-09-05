package auth

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"
)

func newAPIKeyTestDeps(t *testing.T) (*memory.UserStore, *memory.APIKeyStore, *memory.AuditStore, security.IDGenerator, token.TokenGenerator) {
	t.Helper()
	gen, err := token.NewCryptoRandTokenGenerator(32)
	if err != nil {
		t.Fatalf("building token generator: %v", err)
	}
	return memory.NewUserStore(), memory.NewAPIKeyStore(), memory.NewAuditStore(), security.NewUUIDv7Generator(), gen
}

func seedAPIKeyUser(t *testing.T, users *memory.UserStore, id string) {
	t.Helper()
	hasher, err := security.NewBcryptHasher(4)
	if err != nil {
		t.Fatalf("building hasher: %v", err)
	}
	hash, err := hasher.Hash("Tr0ubl3-Fr33!2026")
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}
	if err := users.Create(context.Background(), storeUser(id, id+"+raymondproguy@dev.com", hash)); err != nil {
		t.Fatalf("seeding user: %v", err)
	}
}

// generate is the happy path, called by most tests below.
func generate(t *testing.T, users *memory.UserStore, keys *memory.APIKeyStore, audit *memory.AuditStore, ids security.IDGenerator, gen token.TokenGenerator, userID string, scopes []string, ttl time.Duration) (string, store.APIKey) {
	t.Helper()
	raw, record, err := GenerateAPIKey(context.Background(), users, keys, ids, gen, audit, testLogger{}, userID, "ci deploy", scopes, ttl, "ck")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	return raw, record
}

func TestGenerateAPIKey_ReturnsTheSecretOnceAndStoresOnlyItsHash(t *testing.T) {
	users, keys, audit, ids, gen := newAPIKeyTestDeps(t)
	seedAPIKeyUser(t, users, "user-1")
	ctx := context.Background()

	raw, record := generate(t, users, keys, audit, ids, gen, "user-1", []string{"deploy:write"}, 0)

	if !strings.HasPrefix(raw, "ck_") {
		t.Errorf("raw key %q does not start with the configured prefix", raw)
	}
	// 32 bytes hex-encoded, plus "ck_".
	if len(raw) != 3+64 {
		t.Errorf("raw key length = %d, want %d", len(raw), 3+64)
	}
	if record.KeyHash != "" {
		t.Error("returned record still carries the key hash")
	}
	if record.ExpiresAt != nil {
		t.Errorf("ttl 0 should never expire, got %v", record.ExpiresAt)
	}
	if record.ID == "" || record.UserID != "user-1" || record.Name != "ci deploy" {
		t.Errorf("returned record is wrong: %+v", record)
	}
	if !strings.HasPrefix(raw, record.Prefix) || len(record.Prefix) != 3+8 {
		t.Errorf("prefix %q is not the first 8 characters of %q", record.Prefix, raw)
	}

	stored, err := keys.GetByKeyHash(ctx, token.HashToken(raw))
	if err != nil {
		t.Fatalf("looking the key up by its hash: %v", err)
	}
	if stored.ID != record.ID {
		t.Errorf("stored key ID = %q, want %q", stored.ID, record.ID)
	}
	// The raw secret must appear nowhere in the stored row.
	if strings.Contains(stored.KeyHash, strings.TrimPrefix(raw, "ck_")) {
		t.Error("stored key hash contains the raw secret")
	}
	if stored.CreatedAt.IsZero() {
		t.Error("stored key has no CreatedAt")
	}

	events, err := audit.ListByUser(ctx, "user-1", 10)
	if err != nil {
		t.Fatalf("listing audit events: %v", err)
	}
	if len(events) != 1 || events[0].Type != store.EventAPIKeyCreated {
		t.Fatalf("expected one api_key_created event, got %+v", events)
	}
	if events[0].Metadata["key_id"] != record.ID || events[0].Metadata["prefix"] != record.Prefix {
		t.Errorf("audit metadata does not identify the key: %v", events[0].Metadata)
	}
	if events[0].Metadata["scopes"] != "deploy:write" {
		t.Errorf("audit metadata scopes = %q", events[0].Metadata["scopes"])
	}
}

func TestGenerateAPIKey_KeysAreUnique(t *testing.T) {
	users, keys, audit, ids, gen := newAPIKeyTestDeps(t)
	seedAPIKeyUser(t, users, "user-1")

	first, firstRec := generate(t, users, keys, audit, ids, gen, "user-1", nil, 0)
	second, secondRec := generate(t, users, keys, audit, ids, gen, "user-1", nil, 0)

	if first == second {
		t.Error("two generated keys are identical")
	}
	if firstRec.ID == secondRec.ID {
		t.Error("two generated keys share a row ID")
	}
}

func TestGenerateAPIKey_TTLSetsExpiry(t *testing.T) {
	users, keys, audit, ids, gen := newAPIKeyTestDeps(t)
	seedAPIKeyUser(t, users, "user-1")

	_, record := generate(t, users, keys, audit, ids, gen, "user-1", nil, time.Hour)

	if record.ExpiresAt == nil {
		t.Fatal("expected an expiry")
	}
	if got := record.ExpiresAt.Sub(record.CreatedAt); got != time.Hour {
		t.Errorf("expiry is %v after creation, want 1h", got)
	}
}

func TestGenerateAPIKey_RejectsUnknownUser(t *testing.T) {
	users, keys, audit, ids, gen := newAPIKeyTestDeps(t)

	_, _, err := GenerateAPIKey(context.Background(), users, keys, ids, gen, audit, testLogger{}, "nobody", "", nil, 0, "ck")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected store.ErrNotFound, got %v", err)
	}
}

func TestGenerateAPIKey_RejectsUnusableScopesAndTTL(t *testing.T) {
	users, keys, audit, ids, gen := newAPIKeyTestDeps(t)
	seedAPIKeyUser(t, users, "user-1")
	ctx := context.Background()

	for _, scope := range []string{"", "read write", "read\twrite", "read\n"} {
		_, _, err := GenerateAPIKey(ctx, users, keys, ids, gen, audit, testLogger{}, "user-1", "", []string{"deploy:write", scope}, 0, "ck")
		if !errors.Is(err, ErrInvalidAPIKeyScope) {
			t.Errorf("scope %q: expected ErrInvalidAPIKeyScope, got %v", scope, err)
		}
		// The message must name the offender: "invalid scope" alone
		// tells a host nothing about which of its scopes is wrong.
		if err != nil && !strings.Contains(err.Error(), strconv.Quote(scope)) {
			t.Errorf("scope %q: error %q does not name it", scope, err)
		}
	}

	if _, _, err := GenerateAPIKey(ctx, users, keys, ids, gen, audit, testLogger{}, "user-1", "", nil, -time.Second, "ck"); !errors.Is(err, ErrInvalidAPIKeyTTL) {
		t.Errorf("negative ttl: expected ErrInvalidAPIKeyTTL, got %v", err)
	}

	// Nothing above may have left a key or an audit event behind.
	listed, err := keys.ListByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("listing keys: %v", err)
	}
	if len(listed) != 0 {
		t.Errorf("expected no keys created, got %d", len(listed))
	}
	events, _ := audit.ListByUser(ctx, "user-1", 10)
	if len(events) != 0 {
		t.Errorf("expected no audit events, got %d", len(events))
	}
}

func TestAuthenticateAPIKey_ResolvesUserAndScopes(t *testing.T) {
	users, keys, audit, ids, gen := newAPIKeyTestDeps(t)
	seedAPIKeyUser(t, users, "user-1")
	ctx := context.Background()

	raw, record := generate(t, users, keys, audit, ids, gen, "user-1", []string{"deploy:write", "logs:read"}, time.Hour)

	identity, err := AuthenticateAPIKey(ctx, keys, audit, testLogger{}, raw)
	if err != nil {
		t.Fatalf("AuthenticateAPIKey: %v", err)
	}
	if identity.UserID != "user-1" {
		t.Errorf("UserID = %q, want user-1", identity.UserID)
	}
	if identity.KeyID != record.ID {
		t.Errorf("KeyID = %q, want %q", identity.KeyID, record.ID)
	}
	if identity.Name != "ci deploy" {
		t.Errorf("Name = %q", identity.Name)
	}
	if !identity.HasScope("deploy:write") || !identity.HasScope("logs:read") {
		t.Errorf("granted scopes missing from %v", identity.Scopes)
	}
	// Exact match only: no prefix matching, no hierarchy.
	if identity.HasScope("deploy") || identity.HasScope("deploy:") || identity.HasScope("") {
		t.Error("HasScope matched something it was not granted")
	}

	// A successful authentication is deliberately not audited — it
	// happens on every machine request, and a row per request would
	// bury everything else in the table.
	events, _ := audit.ListByUser(ctx, "user-1", 10)
	if len(events) != 1 || events[0].Type != store.EventAPIKeyCreated {
		t.Errorf("expected only the creation event, got %+v", events)
	}
}

func TestAuthenticateAPIKey_TrimsSurroundingWhitespace(t *testing.T) {
	users, keys, audit, ids, gen := newAPIKeyTestDeps(t)
	seedAPIKeyUser(t, users, "user-1")

	raw, _ := generate(t, users, keys, audit, ids, gen, "user-1", nil, 0)

	// What a key read out of a file or an env var looks like.
	if _, err := AuthenticateAPIKey(context.Background(), keys, audit, testLogger{}, "  "+raw+"\n"); err != nil {
		t.Errorf("expected the trimmed key to authenticate, got %v", err)
	}
}

func TestAuthenticateAPIKey_RejectsUnknownKeysSilently(t *testing.T) {
	users, keys, audit, ids, gen := newAPIKeyTestDeps(t)
	seedAPIKeyUser(t, users, "user-1")
	ctx := context.Background()

	raw, _ := generate(t, users, keys, audit, ids, gen, "user-1", nil, 0)

	for name, presented := range map[string]string{
		"empty":             "",
		"whitespace only":   " \t\n",
		"not a key at all":  "hunter2",
		"right shape":       "ck_" + strings.Repeat("a", 64),
		"prefix only":       "ck_",
		"one byte changed":  raw[:len(raw)-1] + flipLastChar(raw),
		"the prefix stolen": strings.TrimSuffix(raw, raw[len(raw)-8:]),
	} {
		identity, err := AuthenticateAPIKey(ctx, keys, audit, testLogger{}, presented)
		if !errors.Is(err, ErrInvalidAPIKey) {
			t.Errorf("%s: expected ErrInvalidAPIKey, got %v", name, err)
		}
		if identity.UserID != "" || identity.KeyID != "" || identity.Scopes != nil {
			t.Errorf("%s: a rejected key still returned %+v", name, identity)
		}
	}

	// No audit events for any of them: an unrecognised key is
	// unauthenticated internet traffic, and auditing it would hand
	// anyone with a wordlist a write endpoint into the table.
	events, _ := audit.ListByUser(ctx, "user-1", 20)
	if len(events) != 1 {
		t.Errorf("expected only the creation event, got %d: %+v", len(events), events)
	}

	// The real key still works, so the above is not "everything fails".
	if _, err := AuthenticateAPIKey(ctx, keys, audit, testLogger{}, raw); err != nil {
		t.Errorf("the honest key stopped working: %v", err)
	}
}

// flipLastChar returns a hex character that is not the raw key's last.
func flipLastChar(raw string) string {
	if raw[len(raw)-1] == 'a' {
		return "b"
	}
	return "a"
}

func TestAuthenticateAPIKey_RejectsExpiredKeyAndAuditsIt(t *testing.T) {
	users, keys, audit, ids, gen := newAPIKeyTestDeps(t)
	seedAPIKeyUser(t, users, "user-1")
	ctx := context.Background()

	// Expiry is checked against the stored timestamp, so a key created
	// with a negative-in-effect lifetime needs writing directly: the
	// facade refuses a negative ttl on purpose.
	raw, err := seedExpiredKey(ctx, keys, ids, gen, "user-1")
	if err != nil {
		t.Fatalf("seeding an expired key: %v", err)
	}

	if _, err := AuthenticateAPIKey(ctx, keys, audit, testLogger{}, raw); !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("expected ErrInvalidAPIKey, got %v", err)
	}

	events, _ := audit.ListByUser(ctx, "user-1", 10)
	if len(events) != 1 || events[0].Type != store.EventAPIKeyRejected {
		t.Fatalf("expected one api_key_rejected event, got %+v", events)
	}
	if events[0].Metadata["reason"] != "expired" {
		t.Errorf("audit reason = %q, want expired", events[0].Metadata["reason"])
	}
}

func seedExpiredKey(ctx context.Context, keys store.APIKeyStore, ids security.IDGenerator, gen token.TokenGenerator, userID string) (string, error) {
	secret, err := gen.New()
	if err != nil {
		return "", err
	}
	id, err := ids.New()
	if err != nil {
		return "", err
	}
	raw := "ck_" + secret
	expired := time.Now().Add(-time.Minute)
	return raw, keys.Create(ctx, store.APIKey{
		ID:        id,
		UserID:    userID,
		KeyHash:   token.HashToken(raw),
		Prefix:    raw[:11],
		ExpiresAt: &expired,
		CreatedAt: time.Now().Add(-time.Hour),
	})
}

func TestRevokeAPIKey_StopsTheKeyAndAuditsIt(t *testing.T) {
	users, keys, audit, ids, gen := newAPIKeyTestDeps(t)
	seedAPIKeyUser(t, users, "user-1")
	ctx := context.Background()

	raw, record := generate(t, users, keys, audit, ids, gen, "user-1", nil, 0)
	if _, err := AuthenticateAPIKey(ctx, keys, audit, testLogger{}, raw); err != nil {
		t.Fatalf("key did not work before revocation: %v", err)
	}

	if err := RevokeAPIKey(ctx, keys, audit, testLogger{}, "user-1", record.ID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}

	if _, err := AuthenticateAPIKey(ctx, keys, audit, testLogger{}, raw); !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("revoked key still authenticates: %v", err)
	}
	// Revoking twice is not idempotent-and-silent: it reports the same
	// not-found as a key that never existed.
	if err := RevokeAPIKey(ctx, keys, audit, testLogger{}, "user-1", record.ID); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Errorf("second revoke: expected ErrAPIKeyNotFound, got %v", err)
	}
	if err := RevokeAPIKey(ctx, keys, audit, testLogger{}, "user-1", "no-such-key"); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Errorf("unknown key: expected ErrAPIKeyNotFound, got %v", err)
	}

	// created, revoked, rejected — in that order.
	events, _ := audit.ListByUser(ctx, "user-1", 10)
	if len(events) != 3 {
		t.Fatalf("expected 3 audit events, got %d: %+v", len(events), events)
	}
	types := map[store.AuditEventType]bool{}
	for _, e := range events {
		types[e.Type] = true
	}
	for _, want := range []store.AuditEventType{store.EventAPIKeyCreated, store.EventAPIKeyRevoked, store.EventAPIKeyRejected} {
		if !types[want] {
			t.Errorf("missing audit event %q", want)
		}
	}
	for _, e := range events {
		if e.Type == store.EventAPIKeyRejected && e.Metadata["reason"] != "revoked" {
			t.Errorf("rejection reason = %q, want revoked", e.Metadata["reason"])
		}
	}
}

func TestRevokeAPIKey_CannotRevokeAnotherUsersKey(t *testing.T) {
	users, keys, audit, ids, gen := newAPIKeyTestDeps(t)
	seedAPIKeyUser(t, users, "user-1")
	seedAPIKeyUser(t, users, "user-2")
	ctx := context.Background()

	raw, record := generate(t, users, keys, audit, ids, gen, "user-1", nil, 0)

	if err := RevokeAPIKey(ctx, keys, audit, testLogger{}, "user-2", record.ID); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Errorf("expected ErrAPIKeyNotFound, got %v", err)
	}
	// Same error as a nonexistent key, and the key must still work:
	// the wrong user learns nothing and breaks nothing.
	if _, err := AuthenticateAPIKey(ctx, keys, audit, testLogger{}, raw); err != nil {
		t.Errorf("key stopped working after a foreign revoke attempt: %v", err)
	}
}

func TestAuthenticateAPIKey_TouchesLastUsedAtMostEveryFiveMinutes(t *testing.T) {
	users, keys, audit, ids, gen := newAPIKeyTestDeps(t)
	seedAPIKeyUser(t, users, "user-1")
	ctx := context.Background()

	raw, record := generate(t, users, keys, audit, ids, gen, "user-1", nil, 0)

	stored, _ := keys.GetByKeyHash(ctx, token.HashToken(raw))
	if stored.LastUsedAt != nil {
		t.Error("a never-used key should have no LastUsedAt")
	}

	if _, err := AuthenticateAPIKey(ctx, keys, audit, testLogger{}, raw); err != nil {
		t.Fatalf("first authentication: %v", err)
	}
	first, _ := keys.GetByKeyHash(ctx, token.HashToken(raw))
	if first.LastUsedAt == nil {
		t.Fatal("first use did not record LastUsedAt")
	}

	if _, err := AuthenticateAPIKey(ctx, keys, audit, testLogger{}, raw); err != nil {
		t.Fatalf("second authentication: %v", err)
	}
	second, _ := keys.GetByKeyHash(ctx, token.HashToken(raw))
	if !second.LastUsedAt.Equal(*first.LastUsedAt) {
		t.Errorf("LastUsedAt moved on an immediately repeated call: %v then %v", first.LastUsedAt, second.LastUsedAt)
	}

	// Age it past the granularity and the next call writes again.
	stale := time.Now().Add(-apiKeyLastUsedGranularity - time.Minute)
	if err := keys.TouchLastUsed(ctx, record.ID, stale); err != nil {
		t.Fatalf("ageing LastUsedAt: %v", err)
	}
	if _, err := AuthenticateAPIKey(ctx, keys, audit, testLogger{}, raw); err != nil {
		t.Fatalf("third authentication: %v", err)
	}
	third, _ := keys.GetByKeyHash(ctx, token.HashToken(raw))
	if !third.LastUsedAt.After(stale) {
		t.Errorf("a stale LastUsedAt was not refreshed: still %v", third.LastUsedAt)
	}
}

func TestListAPIKeys_NewestFirstWithoutHashesOrRevokedKeys(t *testing.T) {
	users, keys, audit, ids, gen := newAPIKeyTestDeps(t)
	seedAPIKeyUser(t, users, "user-1")
	seedAPIKeyUser(t, users, "user-2")
	ctx := context.Background()

	_, oldest := generate(t, users, keys, audit, ids, gen, "user-1", []string{"a"}, 0)
	_, middle := generate(t, users, keys, audit, ids, gen, "user-1", []string{"b"}, 0)
	_, newest := generate(t, users, keys, audit, ids, gen, "user-1", []string{"c"}, 0)
	_, foreign := generate(t, users, keys, audit, ids, gen, "user-2", nil, 0)

	expiredRaw, err := seedExpiredKey(ctx, keys, ids, gen, "user-1")
	if err != nil {
		t.Fatalf("seeding an expired key: %v", err)
	}
	_ = expiredRaw

	if err := RevokeAPIKey(ctx, keys, audit, testLogger{}, "user-1", middle.ID); err != nil {
		t.Fatalf("revoking the middle key: %v", err)
	}

	listed, err := ListAPIKeys(ctx, keys, "user-1")
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}

	// newest, oldest, expired — the revoked one is gone, the expired
	// one is not, and user-2's key was never in scope.
	if len(listed) != 3 {
		t.Fatalf("expected 3 keys, got %d: %+v", len(listed), listed)
	}
	if listed[0].ID != newest.ID {
		t.Errorf("first listed key = %q, want the newest %q", listed[0].ID, newest.ID)
	}
	if listed[1].ID != oldest.ID {
		t.Errorf("second listed key = %q, want %q", listed[1].ID, oldest.ID)
	}
	if listed[2].ExpiresAt == nil || listed[2].ExpiresAt.After(time.Now()) {
		t.Errorf("expected the expired key last, got %+v", listed[2])
	}
	for _, k := range listed {
		if k.KeyHash != "" {
			t.Errorf("key %q was listed with its hash", k.ID)
		}
		if k.ID == middle.ID {
			t.Error("a revoked key was listed")
		}
		if k.ID == foreign.ID {
			t.Error("another user's key was listed")
		}
	}

	empty, err := ListAPIKeys(ctx, keys, "user-with-nothing")
	if err != nil {
		t.Fatalf("ListAPIKeys for a user with none: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("expected no keys, got %d", len(empty))
	}
}
