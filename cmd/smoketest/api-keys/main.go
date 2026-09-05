// Command api-keys is a standalone, no-database smoke test for API keys
// and machine-to-machine authentication: a long-lived credential a
// user's CI job, deploy script or CLI presents on every request, with
// no password, no session, no refresh token and no second factor —
// there is no human behind it to prompt. What is under test is the
// whole round trip through the public facade (generate, authenticate,
// list, revoke), the fact that the engine keeps only a hash of the key
// it just handed out, every reason a presented key is refused, and the
// deliberate decisions: expiry is optional, lockout does not reach
// keys, and unknown keys are never audited. Run with:
//
//	go run ./cmd/smoketest/api-keys
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/auth"
	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"
)

const (
	email    = "raymondproguy@dev.com"
	password = "Tr0ubl3-Fr33!2026"
	callerIP = "203.0.113.7"
	agent    = "smoketest-agent"
)

var failures int

func main() {
	fmt.Println("cryden — API keys / machine-to-machine auth smoke test")

	theRoundTrip()
	nothingConfiguredNothingChanged()
	listingKeys()
	revocation()
	expiry()
	refusedKeys()
	refusedArguments()
	lockoutDoesNotReachKeys()
	theAuditTrail()
	whatIsActuallyStored()

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
		return
	}
	fmt.Printf("%d CHECK(S) FAILED\n", failures)
	os.Exit(1)
}

// The point of the item: a machine presents one opaque string and the
// engine says which user it is and what it may do.
func theRoundTrip() {
	section("A key authenticates a machine")

	h, ok := newHarness("ck", 0)
	if !ok {
		return
	}
	ctx := context.Background()

	raw, key, err := cryden.GenerateAPIKey(ctx, h.engine, h.userID, "ci deploy", []string{"deploy:write", "logs:read"}, 0)
	check("key generated", err)

	expectTrue("raw key carries the configured prefix", strings.HasPrefix(raw, "ck_"))
	expectCount("raw key length (prefix + 32 hex-encoded bytes)", len(raw), 3+64)
	expectTrue("returned record shows the non-secret prefix fragment", strings.HasPrefix(raw, key.Prefix))
	expectCount("prefix fragment length", len(key.Prefix), 3+8)
	expectTrue("no expiry by default", key.ExpiresAt == nil && !key.Expired())

	identity, err := cryden.AuthenticateAPIKey(ctx, h.engine, raw)
	check("key authenticates", err)
	expectString("resolves to the right user", identity.UserID, h.userID)
	expectString("names the key it was", identity.KeyID, key.ID)
	expectString("carries the key's label", identity.Name, "ci deploy")
	expectTrue("granted scopes are present", identity.HasScope("deploy:write") && identity.HasScope("logs:read"))
	expectTrue("HasScope is exact: no prefixes, no hierarchy", !identity.HasScope("deploy") && !identity.HasScope("deploy:*"))

	// A machine credential travels through env vars and header parsers.
	trimmed, err := cryden.AuthenticateAPIKey(ctx, h.engine, "  "+raw+"\n")
	check("surrounding whitespace is tolerated", err)
	expectString("...and resolves the same user", trimmed.UserID, h.userID)

	stored, err := h.keys.GetByKeyHash(ctx, token.HashToken(raw))
	check("stored row is found by the hash of the raw key", err)
	expectTrue("the raw secret is nowhere in the stored row",
		!strings.Contains(stored.KeyHash+stored.Prefix+stored.Name, strings.TrimPrefix(raw, "ck_")))
}

// Nil Config.APIKeys is the default, and the default changes nothing.
func nothingConfiguredNothingChanged() {
	section("Unconfigured: four functions, one recognisable error")

	engine, err := cryden.New(cryden.Config{
		JWTSecret: "smoketest-jwt-secret",
		Users:     memory.NewUserStore(),
		Sessions:  memory.NewSessionStore(),
		Audit:     memory.NewAuditStore(),
		Logger:    logger.NewNopLogger(),
	})
	check("engine built without an APIKeyStore", err)
	if err != nil {
		return
	}
	ctx := context.Background()

	_, _, genErr := cryden.GenerateAPIKey(ctx, engine, "user-1", "ci", nil, 0)
	expectErrorIs("GenerateAPIKey", genErr, cryden.ErrAPIKeysNotConfigured)
	_, authErr := cryden.AuthenticateAPIKey(ctx, engine, "ck_whatever")
	expectErrorIs("AuthenticateAPIKey", authErr, cryden.ErrAPIKeysNotConfigured)
	_, listErr := cryden.ListAPIKeys(ctx, engine, "user-1")
	expectErrorIs("ListAPIKeys", listErr, cryden.ErrAPIKeysNotConfigured)
	expectErrorIs("RevokeAPIKey", cryden.RevokeAPIKey(ctx, engine, "user-1", "key-1"), cryden.ErrAPIKeysNotConfigured)

	// A password login is untouched by any of this.
	if _, err := cryden.SignUp(ctx, engine, email, password, callerIP); err == nil {
		_, err = cryden.Login(ctx, engine, email, password, callerIP, agent)
	}
	check("ordinary password login still works", err)
}

// The "your API keys" screen, and the only way to learn a key ID after
// the one time it was returned.
func listingKeys() {
	section("Listing a user's keys")

	h, ok := newHarness("acme", 0)
	if !ok {
		return
	}
	ctx := context.Background()

	rawOld, oldest, err := cryden.GenerateAPIKey(ctx, h.engine, h.userID, "laptop cli", nil, 0)
	check("first key generated", err)
	// The store orders by creation time; two keys minted in the same
	// nanosecond would be a coin toss, so this test's second key is
	// deliberately later.
	time.Sleep(2 * time.Millisecond)
	_, newest, err := cryden.GenerateAPIKey(ctx, h.engine, h.userID, "ci deploy", []string{"deploy:write"}, time.Hour)
	check("second key generated", err)

	expectString("a custom prefix is used", newest.Prefix[:5], "acme_")

	listed, err := cryden.ListAPIKeys(ctx, h.engine, h.userID)
	check("keys listed", err)
	expectCount("both keys are listed", len(listed), 2)
	if len(listed) == 2 {
		expectString("newest first", listed[0].ID, newest.ID)
		expectString("...then the older one", listed[1].ID, oldest.ID)
		expectTrue("the listed key shows its scopes", len(listed[0].Scopes) == 1 && listed[0].Scopes[0] == "deploy:write")
		expectTrue("nothing listed has been used yet", listed[0].LastUsedAt == nil && listed[1].LastUsedAt == nil)
	}

	if _, err := cryden.AuthenticateAPIKey(ctx, h.engine, rawOld); err != nil {
		fail(fmt.Sprintf("using the older key: %v", err))
	}
	used, err := cryden.ListAPIKeys(ctx, h.engine, h.userID)
	check("keys listed again after use", err)
	for _, k := range used {
		if k.ID == oldest.ID {
			expectTrue("the used key now shows LastUsedAt", k.LastUsedAt != nil)
		}
	}

	// Somebody else's keys are not this user's business.
	other, err := cryden.ListAPIKeys(ctx, h.engine, "some-other-user")
	check("listing for a user with no keys", err)
	expectCount("...returns nothing", len(other), 0)
}

// Revocation is the mechanism that actually stops a key, and the only
// one that is immediate.
func revocation() {
	section("Revocation")

	h, ok := newHarness("ck", 0)
	if !ok {
		return
	}
	ctx := context.Background()

	raw, key, err := cryden.GenerateAPIKey(ctx, h.engine, h.userID, "ci deploy", nil, 0)
	check("key generated", err)
	_, err = cryden.AuthenticateAPIKey(ctx, h.engine, raw)
	check("key works beforehand", err)

	check("key revoked", cryden.RevokeAPIKey(ctx, h.engine, h.userID, key.ID))

	identity, err := cryden.AuthenticateAPIKey(ctx, h.engine, raw)
	expectErrorIs("the revoked key no longer authenticates", err, auth.ErrInvalidAPIKey)
	expectTrue("...and returns no identity at all", identity.UserID == "" && identity.KeyID == "")

	// Not idempotent-and-silent: a second revoke reports the same
	// not-found as a key that never existed, so a UI can tell the user
	// something changed underneath them.
	expectErrorIs("revoking twice", cryden.RevokeAPIKey(ctx, h.engine, h.userID, key.ID), auth.ErrAPIKeyNotFound)
	expectErrorIs("revoking a key that never existed", cryden.RevokeAPIKey(ctx, h.engine, h.userID, "no-such-key"), auth.ErrAPIKeyNotFound)

	listed, err := cryden.ListAPIKeys(ctx, h.engine, h.userID)
	check("keys listed after revocation", err)
	expectCount("the revoked key is gone from the list", len(listed), 0)

	// One user must not be able to revoke another's key, and must not
	// learn whether it exists.
	survivor, victim, err := cryden.GenerateAPIKey(ctx, h.engine, h.userID, "second key", nil, 0)
	check("replacement key generated", err)
	expectErrorIs("a different user revoking it", cryden.RevokeAPIKey(ctx, h.engine, "another-user", victim.ID), auth.ErrAPIKeyNotFound)
	_, err = cryden.AuthenticateAPIKey(ctx, h.engine, survivor)
	check("...leaves the key working", err)
}

// Expiry is a convenience for hosts that want rotation. It is not the
// thing that stops a leaked key.
func expiry() {
	section("Expiry")

	h, ok := newHarness("ck", 0)
	if !ok {
		return
	}
	ctx := context.Background()

	// One nanosecond, so the key is already past its expiry by the time
	// the next line runs — no sleeping, and the same code path a
	// ninety-day key takes on day ninety-one.
	raw, key, err := cryden.GenerateAPIKey(ctx, h.engine, h.userID, "short-lived", []string{"deploy:write"}, time.Nanosecond)
	check("key generated with a TTL", err)
	expectTrue("the record carries an expiry", key.ExpiresAt != nil)
	expectTrue("APIKey.Expired reports it", key.Expired())

	identity, err := cryden.AuthenticateAPIKey(ctx, h.engine, raw)
	expectErrorIs("an expired key does not authenticate", err, auth.ErrInvalidAPIKey)
	expectTrue("...and returns no identity", identity.UserID == "")

	// Still listed, deliberately: "it expired on Tuesday" is the answer
	// to why a pipeline broke. A revoked key has already been dealt
	// with; an expired one has not.
	listed, err := cryden.ListAPIKeys(ctx, h.engine, h.userID)
	check("keys listed", err)
	expectCount("the expired key is still listed", len(listed), 1)
	if len(listed) == 1 {
		expectTrue("...and marked expired", listed[0].Expired())
	}

	long, _, err := cryden.GenerateAPIKey(ctx, h.engine, h.userID, "long-lived", nil, 90*24*time.Hour)
	check("a 90-day key generated", err)
	_, err = cryden.AuthenticateAPIKey(ctx, h.engine, long)
	check("...authenticates today", err)
}

// Every way a presented key can be wrong, and the one error all of them
// produce.
func refusedKeys() {
	section("Refused keys, all the same way")

	h, ok := newHarness("ck", 0)
	if !ok {
		return
	}
	ctx := context.Background()

	raw, _, err := cryden.GenerateAPIKey(ctx, h.engine, h.userID, "ci deploy", nil, 0)
	check("honest key generated", err)

	for _, tc := range []struct {
		name      string
		presented string
	}{
		{"an empty string", ""},
		{"whitespace only", " \t\n"},
		{"not a key at all", "hunter2"},
		{"the right shape, invented", "ck_" + strings.Repeat("a", 64)},
		{"the prefix with no secret", "ck_"},
		{"the real key, last character changed", raw[:len(raw)-1] + flip(raw[len(raw)-1])},
		{"the real key, truncated", raw[:len(raw)-4]},
		{"the real key with the prefix stripped", strings.TrimPrefix(raw, "ck_")},
		{"the real key, prefix swapped", "acme_" + strings.TrimPrefix(raw, "ck_")},
	} {
		identity, err := cryden.AuthenticateAPIKey(ctx, h.engine, tc.presented)
		if !errors.Is(err, auth.ErrInvalidAPIKey) {
			fail(fmt.Sprintf("%s: expected ErrInvalidAPIKey, got %v", tc.name, err))
			continue
		}
		if identity.UserID != "" || identity.KeyID != "" || identity.Scopes != nil {
			fail(fmt.Sprintf("%s: refused but still returned %+v", tc.name, identity))
			continue
		}
		pass(tc.name + " → ErrInvalidAPIKey, no identity")
	}

	// So the section above is not just "everything fails".
	_, err = cryden.AuthenticateAPIKey(ctx, h.engine, raw)
	check("the honest key still authenticates", err)
}

// What the engine refuses to create in the first place.
func refusedArguments() {
	section("Arguments the engine refuses")

	h, ok := newHarness("ck", 0)
	if !ok {
		return
	}
	ctx := context.Background()

	for _, scope := range []string{"", "read write", "read\twrite"} {
		_, _, err := cryden.GenerateAPIKey(ctx, h.engine, h.userID, "ci", []string{"deploy:write", scope}, 0)
		if !errors.Is(err, auth.ErrInvalidAPIKeyScope) {
			fail(fmt.Sprintf("scope %q: expected ErrInvalidAPIKeyScope, got %v", scope, err))
			continue
		}
		// The message names the offender: a host debugging its own
		// scope list gets nothing from "invalid scope" alone.
		if !strings.Contains(err.Error(), fmt.Sprintf("%q", scope)) {
			fail(fmt.Sprintf("scope %q: error %q does not name it", scope, err))
			continue
		}
		pass(fmt.Sprintf("scope %q → ErrInvalidAPIKeyScope naming it", scope))
	}

	_, _, err := cryden.GenerateAPIKey(ctx, h.engine, h.userID, "ci", nil, -time.Second)
	expectErrorIs("a negative TTL", err, auth.ErrInvalidAPIKeyTTL)

	_, _, err = cryden.GenerateAPIKey(ctx, h.engine, "no-such-user", "ci", nil, 0)
	expectErrorIs("a user that does not exist", err, store.ErrNotFound)

	listed, err := cryden.ListAPIKeys(ctx, h.engine, h.userID)
	check("keys listed", err)
	expectCount("none of the refused calls created anything", len(listed), 0)

	// The prefix is validated once, at construction.
	_, err = cryden.New(cryden.Config{
		JWTSecret:    "smoketest-jwt-secret",
		Users:        memory.NewUserStore(),
		Sessions:     memory.NewSessionStore(),
		Audit:        memory.NewAuditStore(),
		APIKeys:      memory.NewAPIKeyStore(),
		APIKeyPrefix: "ck_v2",
		Logger:       logger.NewNopLogger(),
	})
	expectErrorIs("an APIKeyPrefix containing the separator", err, cryden.ErrInvalidAPIKeyPrefix)
}

// The decision worth demonstrating rather than just documenting: an
// account locked out by failed password attempts keeps its keys.
func lockoutDoesNotReachKeys() {
	section("Lockout does not reach keys")

	h, ok := newHarness("ck", 2)
	if !ok {
		return
	}
	ctx := context.Background()

	raw, _, err := cryden.GenerateAPIKey(ctx, h.engine, h.userID, "ci deploy", nil, 0)
	check("key generated", err)

	// Two wrong passwords is the configured threshold here.
	for i := 0; i < 2; i++ {
		if _, err := cryden.Login(ctx, h.engine, email, "wrong-password", callerIP, agent); err == nil {
			fail("a wrong password logged in")
		}
	}
	_, err = cryden.Login(ctx, h.engine, email, password, callerIP, agent)
	expectErrorIs("the account is now locked for passwords", err, auth.ErrAccountLocked)

	// If lockout reached keys, anyone who knows a developer's email
	// address could take down that account's production integrations by
	// failing to log in as them a few times.
	identity, err := cryden.AuthenticateAPIKey(ctx, h.engine, raw)
	check("the API key still authenticates", err)
	expectString("...as the same user", identity.UserID, h.userID)
}

// What lands in the audit table, and — the part that matters — what
// deliberately does not.
func theAuditTrail() {
	section("The audit trail")

	h, ok := newHarness("ck", 0)
	if !ok {
		return
	}
	ctx := context.Background()

	raw, key, err := cryden.GenerateAPIKey(ctx, h.engine, h.userID, "ci deploy", []string{"deploy:write"}, 0)
	check("key generated", err)

	// Filtered to the api_key_* rows: SignUp wrote a user_signed_up
	// event of its own, and this section is about what keys record.
	events := h.keyEvents()
	expectCount("one key event so far", len(events), 1)
	if len(events) == 1 {
		expectString("...and it is api_key_created", string(events[0].Type), string(store.EventAPIKeyCreated))
		expectString("naming the key", events[0].Metadata["key_id"], key.ID)
		expectString("naming its prefix", events[0].Metadata["prefix"], key.Prefix)
		expectString("naming its scopes", events[0].Metadata["scopes"], "deploy:write")
	}

	// A key is presented on every machine request. A row per request
	// would bury everything else in the table.
	for i := 0; i < 5; i++ {
		if _, err := cryden.AuthenticateAPIKey(ctx, h.engine, raw); err != nil {
			fail(fmt.Sprintf("successful authentication %d: %v", i, err))
		}
	}
	expectCount("five successful uses record nothing", len(h.keyEvents()), 1)

	// Neither does an unrecognised key: it is unauthenticated traffic
	// from anywhere on the internet, and auditing it would hand anyone
	// with a wordlist a write endpoint into this table.
	for i := 0; i < 5; i++ {
		if _, err := cryden.AuthenticateAPIKey(ctx, h.engine, "ck_"+strings.Repeat("f", 64)); !errors.Is(err, auth.ErrInvalidAPIKey) {
			fail(fmt.Sprintf("unknown key %d: got %v", i, err))
		}
	}
	expectCount("five unknown keys record nothing either", len(h.keyEvents()), 1)

	// A key that exists but is no longer usable is different: only
	// somebody who once held a real credential can trigger it.
	check("key revoked", cryden.RevokeAPIKey(ctx, h.engine, h.userID, key.ID))
	if _, err := cryden.AuthenticateAPIKey(ctx, h.engine, raw); !errors.Is(err, auth.ErrInvalidAPIKey) {
		fail(fmt.Sprintf("revoked key: got %v", err))
	}

	events = h.keyEvents()
	expectCount("three key events now", len(events), 3)
	expectTrue("api_key_revoked was recorded", hasEvent(events, store.EventAPIKeyRevoked, ""))
	expectTrue("api_key_rejected was recorded, reason revoked", hasEvent(events, store.EventAPIKeyRejected, "revoked"))
}

// Printed rather than asserted: the shape of the thing a host has to
// keep secret, and the shape of what the engine keeps instead.
func whatIsActuallyStored() {
	section("What is actually stored")

	h, ok := newHarness("ck", 0)
	if !ok {
		return
	}
	ctx := context.Background()

	raw, key, err := cryden.GenerateAPIKey(ctx, h.engine, h.userID, "ci deploy", []string{"deploy:write"}, 0)
	check("key generated", err)

	stored, err := h.keys.GetByKeyHash(ctx, token.HashToken(raw))
	check("stored row read back", err)

	fmt.Println("   raw key (returned exactly once):", raw)
	fmt.Println("   stored key_hash (SHA-256):      ", stored.KeyHash)
	fmt.Println("   stored prefix (shown in a UI):  ", key.Prefix)
	fmt.Println()
	fmt.Println("   The key is a bearer credential: anyone holding that first")
	fmt.Println("   line authenticates as this user until it is revoked. It is")
	fmt.Println("   hashed, not encrypted — there is no way back from line two")
	fmt.Println("   to line one, which is also why nothing can ever show it")
	fmt.Println("   again.")

	expectTrue("the hash is SHA-256 hex", len(stored.KeyHash) == 64)
	expectTrue("the hash is not the key", stored.KeyHash != raw && !strings.Contains(raw, stored.KeyHash))
}

// ---- harness ----

type harness struct {
	engine *cryden.Engine
	keys   *memory.APIKeyStore
	audit  *memory.AuditStore
	userID string
}

// newHarness builds an engine with an APIKeyStore and signs the
// standard user up. lockoutThreshold of 0 leaves the engine default.
func newHarness(prefix string, lockoutThreshold int) (*harness, bool) {
	keys := memory.NewAPIKeyStore()
	audit := memory.NewAuditStore()
	engine, err := cryden.New(cryden.Config{
		JWTSecret: "smoketest-jwt-secret",
		Users:     memory.NewUserStore(),
		Sessions:  memory.NewSessionStore(),
		Audit:     audit,
		APIKeys:   keys,
		// Repeated logins from one address are this test's normal shape,
		// not an attack on it.
		RateLimitAttempts: 1000,
		APIKeyPrefix:      prefix,
		LockoutThreshold:  lockoutThreshold,
		// The engine logs several lines per call; this test is about the
		// ✓/✗ lines, so those go nowhere.
		Logger: logger.NewNopLogger(),
	})
	if err != nil {
		fail(fmt.Sprintf("building the engine: %v", err))
		return nil, false
	}

	user, err := cryden.SignUp(context.Background(), engine, email, password, callerIP)
	if err != nil {
		fail(fmt.Sprintf("signing the user up: %v", err))
		return nil, false
	}
	return &harness{engine: engine, keys: keys, audit: audit, userID: user.ID}, true
}

func (h *harness) events() []store.AuditEvent {
	events, err := h.audit.ListByUser(context.Background(), h.userID, 50)
	if err != nil {
		fail(fmt.Sprintf("listing audit events: %v", err))
		return nil
	}
	return events
}

// keyEvents narrows the user's audit trail to the API key events, so a
// count here is not thrown off by the signup that created the account.
func (h *harness) keyEvents() []store.AuditEvent {
	var out []store.AuditEvent
	for _, e := range h.events() {
		switch e.Type {
		case store.EventAPIKeyCreated, store.EventAPIKeyRevoked, store.EventAPIKeyRejected:
			out = append(out, e)
		}
	}
	return out
}

func hasEvent(events []store.AuditEvent, want store.AuditEventType, reason string) bool {
	for _, e := range events {
		if e.Type == want && (reason == "" || e.Metadata["reason"] == reason) {
			return true
		}
	}
	return false
}

// flip returns a hex character that is not c.
func flip(c byte) string {
	if c == 'a' {
		return "b"
	}
	return "a"
}

func section(name string) {
	fmt.Printf("\n— %s\n", name)
}

func check(step string, err error) {
	if err != nil {
		fail(fmt.Sprintf("%s: unexpected error: %v", step, err))
		return
	}
	pass(step)
}

func expectErrorIs(step string, got, want error) {
	if !errors.Is(got, want) {
		fail(fmt.Sprintf("%s: got %v, want %v", step, got, want))
		return
	}
	pass(fmt.Sprintf("%s → %v", step, want))
}

func expectString(step, got, want string) {
	if got != want {
		fail(fmt.Sprintf("%s: got %q, want %q", step, got, want))
		return
	}
	pass(step)
}

func expectCount(step string, got, want int) {
	if got != want {
		fail(fmt.Sprintf("%s: got %d, want %d", step, got, want))
		return
	}
	pass(step)
}

func expectTrue(step string, ok bool) {
	if !ok {
		fail(step)
		return
	}
	pass(step)
}

func pass(step string) {
	fmt.Println("✓", step)
}

func fail(msg string) {
	failures++
	fmt.Println("✗", msg)
}
