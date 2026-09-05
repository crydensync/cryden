// Command argon2id-hasher is a standalone, no-database smoke test for
// Argon2id as a second trusted password hasher: the PHC-encoded format
// that makes verification stateless, dispatch across a users table that
// holds both algorithms at once, the upgrade-on-login that drains such a
// table without a migration job, and the negative half of all of it —
// malformed, tampered, downgraded and unreadable stored hashes, a wrong
// password, and a users table that refuses the rewrite. Run with:
//
//	go run ./cmd/smoketest/argon2id-hasher
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
	"golang.org/x/crypto/bcrypt"
)

const (
	email    = "raymondproguy@dev.com"
	password = "Tr0ubl3-Fr33!2026"
	wrong    = "Tr0ubl3-Fr33!2025"
	callerIP = "1.2.3.4"
	agent    = "smoketest/1.0"
)

// Every Argon2id parameter here is deliberately at or near its floor.
// This test is about which algorithm ends up in the table and whether
// old hashes still verify, never about how long a hash takes; the
// defaults (64 MiB a call) would make it slow without checking anything
// more.
var fast = security.Argon2idParams{
	Memory:      64,
	Iterations:  1,
	Parallelism: 1,
	SaltLength:  8,
	KeyLength:   16,
}

var failures int

func main() {
	ctx := context.Background()

	section("Constructor: defaults and validation")
	defaulted, err := security.NewArgon2idHasher(security.Argon2idParams{})
	check("zero params construct a hasher", err)
	expectBool("zero params mean DefaultArgon2idParams",
		defaulted != nil && defaulted.Params() == security.DefaultArgon2idParams, true)
	expectBool("the defaults are RFC 9106's second recommended option (64 MiB, t=3, p=4)",
		security.DefaultArgon2idParams.Memory == 64*1024 &&
			security.DefaultArgon2idParams.Iterations == 3 &&
			security.DefaultArgon2idParams.Parallelism == 4, true)

	// x/crypto panics on t=0 or p=0 rather than returning an error, so
	// these are not stylistic validations — they are what keeps a
	// misconfiguration from taking the process down on first login.
	for name, params := range map[string]security.Argon2idParams{
		"no iterations":               {Memory: 64, Iterations: 0, Parallelism: 1, SaltLength: 8, KeyLength: 16},
		"no parallelism":              {Memory: 64, Iterations: 1, Parallelism: 0, SaltLength: 8, KeyLength: 16},
		"memory below 8 KiB per lane": {Memory: 16, Iterations: 1, Parallelism: 4, SaltLength: 8, KeyLength: 16},
		"memory above 4 GiB":          {Memory: 5 * 1024 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16},
		"salt under 8 bytes":          {Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 4, KeyLength: 16},
		"key under 16 bytes":          {Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 8},
		"one field set alone":         {Memory: 64},
	} {
		_, err := security.NewArgon2idHasher(params)
		expectSentinel("rejected: "+name, err, security.ErrInvalidArgon2idParams)
	}

	argon2id, err := security.NewArgon2idHasher(fast)
	check("a valid parameter set constructs a hasher", err)
	if argon2id == nil {
		fmt.Println("\ncannot continue without a hasher")
		os.Exit(1)
	}

	section("Hash and verify")
	hash, err := argon2id.Hash(password)
	check("hashing a password", err)
	expectBool("the password does not appear in its own hash", strings.Contains(hash, password), false)
	check("the correct password verifies", argon2id.Compare(hash, password))
	expectSentinel("the wrong password does not", argon2id.Compare(hash, wrong), security.ErrPasswordMismatch)
	expectSentinel("neither does an empty one", argon2id.Compare(hash, ""), security.ErrPasswordMismatch)

	second, err := argon2id.Hash(password)
	check("hashing the same password again", err)
	expectBool("a fresh salt per hash: the same password hashes differently", hash == second, false)
	check("and both still verify", argon2id.Compare(second, password))

	section("The encoded format is the migration story")
	parts := strings.Split(hash, "$")
	expectBool("six $-separated segments", len(parts) == 6, true)
	if len(parts) == 6 {
		expectString("algorithm segment", parts[1], "argon2id")
		expectString("version segment", parts[2], "v=19")
		expectString("parameter segment", parts[3], "m=64,t=1,p=1")
		salt, saltErr := base64.RawStdEncoding.DecodeString(parts[4])
		key, keyErr := base64.RawStdEncoding.DecodeString(parts[5])
		expectBool("salt is unpadded standard base64", saltErr == nil, true)
		expectBool("key is unpadded standard base64", keyErr == nil, true)
		expectBool("salt and key are the configured lengths",
			len(salt) == int(fast.SaltLength) && len(key) == int(fast.KeyLength), true)
	}
	expectBool("every parameter a verifier needs travels inside the hash",
		strings.Contains(hash, "m=64,t=1,p=1"), true)

	section("Raising the cost does not invalidate old credentials")
	stronger, err := security.NewArgon2idHasher(security.Argon2idParams{
		Memory: 256, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	check("constructing a more expensive hasher", err)
	check("a hash written under the old parameters still verifies", stronger.Compare(hash, password))
	expectSentinel("and still rejects the wrong password", stronger.Compare(hash, wrong), security.ErrPasswordMismatch)
	expectBool("while new hashes use the new parameters", func() bool {
		fresh, hashErr := stronger.Hash(password)
		return hashErr == nil && strings.Contains(fresh, "m=256,t=2,p=1")
	}(), true)

	section("Stored hashes that must never verify")
	tampered := func(from, to string) string { return strings.Replace(hash, from, to, 1) }
	flipped := func() string {
		p := strings.Split(hash, "$")
		key, _ := base64.RawStdEncoding.DecodeString(p[5])
		key[0] ^= 0xff
		p[5] = base64.RawStdEncoding.EncodeToString(key)
		return strings.Join(p, "$")
	}()
	// Each of these is something that could genuinely be sitting in a
	// users table: hand-edited, truncated by a narrow column, written by
	// another library, or simply not Argon2id at all.
	for name, stored := range map[string]string{
		"empty string":                                   "",
		"not a hash at all":                              "hunter2",
		"a bcrypt hash":                                  "$2b$04$LN.f0Ax0dvXQwGgtDbabkeUQMTsZEBWaVGSFrjLwFbCOMXW/vHt/i",
		"argon2i, not argon2id":                          tampered("argon2id", "argon2i"),
		"a hash cut off mid-parameters":                  hash[:20],
		"an unreadable version":                          tampered("v=19", "v=x"),
		"a missing parameter":                            tampered("m=64,t=1,p=1", "m=64,t=1"),
		"trailing junk in params":                        tampered("m=64,t=1,p=1", "m=64,t=1,p=1,x=9"),
		"zero iterations (panics x/crypto if unguarded)": tampered("m=64,t=1,p=1", "m=64,t=0,p=1"),
		"zero parallelism (same)":                        tampered("m=64,t=1,p=1", "m=64,t=1,p=0"),
		"a 4 TiB memory cost (same)":                     tampered("m=64,t=1,p=1", "m=4294967295,t=1,p=1"),
		"a salt that is not base64":                      "$argon2id$v=19$m=64,t=1,p=1$not!base64!$AAAAAAAAAAAAAAAAAAAAAA",
		"an empty salt and key":                          "$argon2id$v=19$m=64,t=1,p=1$$",
	} {
		expectSentinel("rejected: "+name, argon2id.Compare(stored, password), security.ErrMalformedHash)
	}
	expectSentinel("rejected: a future Argon2id version, named as such",
		argon2id.Compare(tampered("v=19", "v=20"), password), security.ErrUnsupportedHashVersion)
	expectSentinel("rejected: one flipped byte of the derived key",
		argon2id.Compare(flipped, password), security.ErrPasswordMismatch)
	// A hash truncated inside its base64 key is not detectably malformed:
	// a shorter key is a legal parameter choice, and the decoder accepts
	// whatever length it finds so that hashes written under other
	// KeyLengths keep verifying. It reads as a mismatch instead, which is
	// the outcome that actually matters — it does not verify.
	expectSentinel("rejected: a hash truncated inside its key",
		argon2id.Compare(hash[:len(hash)-10], password), security.ErrPasswordMismatch)

	section("One table, both algorithms")
	cheapBcrypt, err := security.NewBcryptHasher(bcrypt.MinCost)
	check("constructing a bcrypt hasher", err)
	bcryptHash, err := cheapBcrypt.Hash(password)
	check("hashing a password with bcrypt", err)
	expectString("bcrypt hashes are identified as bcrypt", string(security.IdentifyHash(bcryptHash)), "bcrypt")
	expectString("argon2id hashes are identified as argon2id", string(security.IdentifyHash(hash)), "argon2id")
	for _, prefix := range []string{"$2a$", "$2b$", "$2x$", "$2y$"} {
		expectString("all four bcrypt prefixes are recognised: "+prefix,
			string(security.IdentifyHash(prefix+"04$LN.f0Ax0dvXQwGgtDbabkeUQMTsZEBWaVGSFrjLwFbCOMXW/vHt/i")), "bcrypt")
	}
	for _, other := range []string{"$argon2i$v=19$m=64,t=1,p=1$c2FsdA$AAAA", "$scrypt$ln=16$c2FsdA$AAAA", "hunter2", ""} {
		expectString("anything else is unknown, not guessed at: "+truncate(other),
			string(security.IdentifyHash(other)), "unknown")
	}

	// A MultiHasher over each algorithm: the point is that both verify
	// both, so which one is configured today never decides whether
	// yesterday's hashes still work.
	newPrimary := security.NewMultiHasher(argon2id)
	oldPrimary := security.NewMultiHasher(cheapBcrypt)
	check("argon2id primary verifies a bcrypt hash", newPrimary.Compare(bcryptHash, password))
	check("argon2id primary verifies an argon2id hash", newPrimary.Compare(hash, password))
	check("bcrypt primary verifies an argon2id hash", oldPrimary.Compare(hash, password))
	check("bcrypt primary verifies a bcrypt hash", oldPrimary.Compare(bcryptHash, password))
	expectBool("a wrong password fails against both, whichever is primary",
		newPrimary.Compare(bcryptHash, wrong) != nil && oldPrimary.Compare(hash, wrong) != nil, true)
	expectBool("new hashes are written by the primary only", func() bool {
		fromNew, err1 := newPrimary.Hash(password)
		fromOld, err2 := oldPrimary.Hash(password)
		return err1 == nil && err2 == nil &&
			security.IdentifyHash(fromNew) == security.AlgorithmArgon2id &&
			security.IdentifyHash(fromOld) == security.AlgorithmBcrypt
	}(), true)
	expectBool("wrapping a MultiHasher returns it unchanged, never nested",
		security.NewMultiHasher(newPrimary) == newPrimary, true)

	section("Which hashes are considered out of date")
	expectBool("a bcrypt hash is, under an argon2id primary", newPrimary.NeedsRehash(bcryptHash), true)
	expectBool("an argon2id hash at the configured parameters is not", newPrimary.NeedsRehash(hash), false)
	expectBool("an unreadable hash is, by definition", newPrimary.NeedsRehash("hunter2"), true)
	strongStored, err := stronger.Hash(password)
	check("hashing under stronger parameters", err)
	expectBool("a stronger stored hash is left alone, never downgraded",
		newPrimary.NeedsRehash(strongStored), false)
	weakerConfigured, err := security.NewArgon2idHasher(security.Argon2idParams{
		Memory: 64, Iterations: 1, Parallelism: 2, SaltLength: 8, KeyLength: 16,
	})
	check("constructing a hasher that differs only in parallelism", err)
	expectBool("a parallelism-only difference is not a reason to rehash the whole table",
		security.NewMultiHasher(weakerConfigured).NeedsRehash(hash), false)
	dearerBcrypt, err := security.NewBcryptHasher(6)
	check("constructing bcrypt at a higher cost", err)
	expectBool("a bcrypt hash below the configured cost is out of date",
		security.NewMultiHasher(dearerBcrypt).NeedsRehash(bcryptHash), true)
	expectBool("a bcrypt hash above it is not", security.NewMultiHasher(cheapBcrypt).NeedsRehash(strongBcrypt(dearerBcrypt)), false)
	expectBool("a hasher that does not implement Rehasher never triggers an upgrade",
		security.NewMultiHasher(plainHasher{inner: cheapBcrypt}).NeedsRehash(bcryptHash), false)

	section("The engine's default is unchanged")
	users, sessions, audit := memory.NewUserStore(), memory.NewSessionStore(), memory.NewAuditStore()
	before, err := newEngine(users, sessions, audit, nil)
	check("an engine with no Hasher configured", err)
	_, err = cryden.SignUp(ctx, before, email, password, callerIP)
	check("signing up under it", err)
	expectAlgorithm("the account is hashed with bcrypt, as it always was", users, "bcrypt")
	_, err = cryden.Login(ctx, before, email, password, callerIP, agent)
	check("and logs in", err)
	expectUpgrades("no upgrade happened: nothing was out of date", audit, 0)

	section("Switching to Argon2id migrates on login")
	after, err := newEngine(users, sessions, audit, argon2id)
	check("a second engine over the same stores, configured for Argon2id", err)

	// The wrong password must not reach the rewrite: if it did, every
	// guess in a spray would cost the victim's account an Argon2id hash
	// and a write.
	_, err = cryden.Login(ctx, after, email, wrong, callerIP, agent)
	expectFailed("a wrong password is still rejected", err)
	expectAlgorithm("and left the stored hash alone", users, "bcrypt")
	expectUpgrades("still no upgrade recorded", audit, 0)

	tokens, err := cryden.Login(ctx, after, email, password, callerIP, agent)
	check("the correct password logs in against the new configuration", err)
	expectBool("and issued a real session", tokens.AccessToken != "" && tokens.RefreshToken != "", true)
	expectAlgorithm("the stored hash is now argon2id", users, "argon2id")
	expectUpgrades("one password_hash_upgraded event", audit, 1)
	expectUpgradeMetadata("recorded as bcrypt → argon2id", audit)

	_, err = cryden.Login(ctx, after, email, password, callerIP, agent)
	check("logging in again after the rewrite", err)
	expectUpgrades("no second upgrade: the hash is current now", audit, 1)
	_, err = cryden.Login(ctx, after, email, wrong, callerIP, agent)
	expectFailed("and the wrong password is still wrong afterwards", err)

	// The account has to remain usable by an operator who rolls the
	// configuration back — which is exactly what dispatch buys.
	rolledBack, err := newEngine(users, sessions, audit, cheapBcrypt)
	check("rolling the configuration back to bcrypt", err)
	_, err = cryden.Login(ctx, rolledBack, email, password, callerIP, agent)
	check("the migrated account still logs in under the old configuration", err)
	expectAlgorithm("though the bcrypt engine now considers it out of date and rewrites it", users, "bcrypt")

	section("Raising bcrypt's cost is the same mechanism")
	costUsers, costSessions, costAudit := memory.NewUserStore(), memory.NewSessionStore(), memory.NewAuditStore()
	cheapEngine, err := newEngineAtCost(costUsers, costSessions, costAudit, bcrypt.MinCost)
	check("an engine at bcrypt's minimum cost", err)
	_, err = cryden.SignUp(ctx, cheapEngine, email, password, callerIP)
	check("signing up under it", err)
	expectCost("the account is hashed at cost 4", costUsers, bcrypt.MinCost)

	dearerEngine, err := newEngineAtCost(costUsers, costSessions, costAudit, 6)
	check("the same stores behind an engine at cost 6", err)
	_, err = cryden.Login(ctx, dearerEngine, email, password, callerIP, agent)
	check("logging in", err)
	expectCost("the stored hash was rewritten at the new cost", costUsers, 6)
	expectUpgrades("and recorded as an upgrade", costAudit, 1)

	section("Changing a password needs none of this")
	changeUsers, changeSessions, changeAudit := memory.NewUserStore(), memory.NewSessionStore(), memory.NewAuditStore()
	legacyEngine, err := newEngine(changeUsers, changeSessions, changeAudit, nil)
	check("an engine on the old configuration", err)
	user, err := cryden.SignUp(ctx, legacyEngine, email, password, callerIP)
	check("signing up under it", err)

	modernEngine, err := newEngine(changeUsers, changeSessions, changeAudit, argon2id)
	check("switching the configuration to Argon2id", err)
	check("changing the password", cryden.ChangePassword(ctx, modernEngine, user.ID, password, "N3w-P4ssw0rd!2026"))
	expectAlgorithm("the new password was written with the configured hasher", changeUsers, "argon2id")
	expectUpgrades("with no upgrade event: it was a new hash, not a rewrite of an old one", changeAudit, 0)
	_, err = cryden.Login(ctx, modernEngine, email, "N3w-P4ssw0rd!2026", callerIP, agent)
	check("and the new password logs in", err)
	_, err = cryden.Login(ctx, modernEngine, email, password, callerIP, agent)
	expectFailed("while the old one no longer does", err)

	section("A users table that refuses the rewrite")
	// Read-only replica, tightened grants, full disk: the login already
	// succeeded, so it must not be turned into a failure by an upgrade
	// nobody asked for.
	roUsers := memory.NewUserStore()
	roHash, err := cheapBcrypt.Hash(password)
	check("hashing an account with bcrypt", err)
	check("storing it", roUsers.Create(ctx, store.User{ID: "user-1", Email: email, PasswordHash: roHash}))
	roAudit := memory.NewAuditStore()
	roEngine, err := newEngine(readOnlyPasswords{UserStore: roUsers}, memory.NewSessionStore(), roAudit, argon2id)
	check("an engine over a store that rejects password writes", err)

	tokens, err = cryden.Login(ctx, roEngine, email, password, callerIP, agent)
	check("the login still succeeds", err)
	expectBool("and still issues tokens", tokens.AccessToken != "" && tokens.RefreshToken != "", true)
	expectAlgorithm("the stored hash is untouched", roUsers, "bcrypt")
	expectUpgrades("and nothing claims otherwise", roAudit, 0)
	_, err = cryden.Login(ctx, roEngine, email, password, callerIP, agent)
	check("the next login tries again and still works", err)

	fmt.Println()
	if failures > 0 {
		fmt.Printf("%d CHECK(S) FAILED\n", failures)
		os.Exit(1)
	}
	fmt.Println("ALL CHECKS PASSED")
}

// newEngine wires an engine over the given stores with hasher as
// Config.Hasher — nil meaning "leave it unset," i.e. the default a host
// gets without knowing this option exists. BcryptCost is pinned to the
// minimum throughout: this test measures which algorithm was used, never
// how long it took.
func newEngine(users store.UserStore, sessions *memory.SessionStore, audit *memory.AuditStore, hasher security.Hasher) (*cryden.Engine, error) {
	return cryden.New(cryden.Config{
		JWTSecret:  "smoketest-secret",
		Users:      users,
		Sessions:   sessions,
		Audit:      audit,
		BcryptCost: bcrypt.MinCost,
		Hasher:     hasher,
	})
}

func newEngineAtCost(users store.UserStore, sessions *memory.SessionStore, audit *memory.AuditStore, cost int) (*cryden.Engine, error) {
	return cryden.New(cryden.Config{
		JWTSecret:  "smoketest-secret",
		Users:      users,
		Sessions:   sessions,
		Audit:      audit,
		BcryptCost: cost,
	})
}

// plainHasher implements security.Hasher and nothing else — a host's own
// implementation, written before Rehasher existed.
type plainHasher struct{ inner security.Hasher }

func (p plainHasher) Hash(password string) (string, error) { return p.inner.Hash(password) }
func (p plainHasher) Compare(hash, password string) error  { return p.inner.Compare(hash, password) }

// readOnlyPasswords accepts every store operation except the one the
// upgrade needs.
type readOnlyPasswords struct {
	*memory.UserStore
}

func (readOnlyPasswords) UpdatePasswordHash(context.Context, string, string) error {
	return errors.New("read-only replica")
}

func strongBcrypt(hasher *security.BcryptHasher) string {
	hash, err := hasher.Hash(password)
	if err != nil {
		fail("hashing with the dearer bcrypt hasher: " + err.Error())
	}
	return hash
}

func storedFor(users store.UserStore) string {
	user, err := users.GetByEmail(context.Background(), email)
	if err != nil {
		fail("reading the stored user back: " + err.Error())
		return ""
	}
	return user.PasswordHash
}

func expectAlgorithm(step string, users store.UserStore, want string) {
	got := string(security.IdentifyHash(storedFor(users)))
	if got != want {
		fail(fmt.Sprintf("%s — stored hash is %s, want %s", step, got, want))
		return
	}
	pass(step)
}

func expectCost(step string, users store.UserStore, want int) {
	got, err := bcrypt.Cost([]byte(storedFor(users)))
	if err != nil {
		fail(fmt.Sprintf("%s — stored hash has no readable bcrypt cost: %v", step, err))
		return
	}
	if got != want {
		fail(fmt.Sprintf("%s — cost is %d, want %d", step, got, want))
		return
	}
	pass(step)
}

func upgradeEvents(audit *memory.AuditStore) []store.AuditEvent {
	events, err := audit.SearchByType(context.Background(), store.EventPasswordHashUpgraded, 100)
	if err != nil {
		fail("searching the audit trail: " + err.Error())
		return nil
	}
	return events
}

func expectUpgrades(step string, audit *memory.AuditStore, want int) {
	if got := len(upgradeEvents(audit)); got != want {
		fail(fmt.Sprintf("%s — %d password_hash_upgraded event(s), want %d", step, got, want))
		return
	}
	pass(step)
}

// The metadata is what an operator watching a migration drain actually
// reads, so "an event happened" is not enough to check.
func expectUpgradeMetadata(step string, audit *memory.AuditStore) {
	events := upgradeEvents(audit)
	if len(events) == 0 {
		fail(step + " — no event to inspect")
		return
	}
	e := events[0]
	if e.Metadata["from"] != "bcrypt" || e.Metadata["to"] != "argon2id" {
		fail(fmt.Sprintf("%s — metadata is %v, want from=bcrypt to=argon2id", step, e.Metadata))
		return
	}
	if e.UserID == "" || e.IP != callerIP {
		fail(fmt.Sprintf("%s — event carries user %q and IP %q", step, e.UserID, e.IP))
		return
	}
	if strings.Contains(fmt.Sprint(e.Metadata), password) {
		fail(step + " — the password reached the audit trail")
		return
	}
	pass(step)
}

func expectSentinel(step string, got, want error) {
	if !errors.Is(got, want) {
		fail(fmt.Sprintf("%s — got %v, want %v", step, got, want))
		return
	}
	pass(step)
}

func expectFailed(step string, got error) {
	if got == nil {
		fail(step + " — expected an error, got none")
		return
	}
	pass(step)
}

func expectBool(step string, got, want bool) {
	if got != want {
		fail(fmt.Sprintf("%s — got %v, want %v", step, got, want))
		return
	}
	pass(step)
}

func expectString(step, got, want string) {
	if got != want {
		fail(fmt.Sprintf("%s — got %q, want %q", step, got, want))
		return
	}
	pass(step)
}

func check(step string, err error) {
	if err != nil {
		fail(step + " — " + err.Error())
		return
	}
	pass(step)
}

func truncate(s string) string {
	if s == "" {
		return "(empty)"
	}
	if len(s) > 24 {
		return s[:24] + "…"
	}
	return s
}

func section(name string) { fmt.Printf("\n— %s\n", name) }
func pass(step string)    { fmt.Println("✓", step) }
func fail(msg string) {
	failures++
	fmt.Println("✗", msg)
}
