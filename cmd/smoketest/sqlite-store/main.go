// Command sqlite-store is a standalone smoke test for the SQLite
// storage backend: the schema and its pragmas, a real engine running
// end to end over it, the hand-written cascade that a host's forgotten
// foreign_keys pragma must not be able to defeat, the TEXT timestamp
// format the whole schema's ordering rests on, the one Postgres-ism
// that needed no translation and the ones that did, and the read-only
// handle the AI query surface is supposed to be given. Run with:
//
//	go run ./cmd/smoketest/sqlite-store
//
// No server and no Postgres — but unlike the other smoke tests here,
// not entirely in memory either: it writes databases under a temporary
// directory and removes them at the end. A file is what a host app
// actually runs, and WAL, busy_timeout and mode=ro only mean anything
// on one.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/ai"
	"github.com/crydensync/cryden/v2/auth"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/sqlite"
	"github.com/crydensync/cryden/v2/token"
)

const (
	email    = "raymondproguy@dev.com"
	password = "Tr0ubl3-Fr33!2026"

	homeIP   = "1.2.3.4"
	officeIP = "203.0.113.7"
	attackIP = "198.51.100.66"

	firefoxLinux = "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"

	// The pragmas the package doc insists on, in the DSN, which is the
	// only place a *sql.DB pool can carry them.
	goodPragmas = "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
)

var (
	failures int
	tempDir  string
	dbSeq    int
)

func main() {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "cryden-sqlite-smoketest-")
	if err != nil {
		fmt.Println("✗ creating a temporary directory:", err)
		os.Exit(1)
	}
	tempDir = dir
	defer os.RemoveAll(tempDir)

	schemaAndPragmas(ctx)
	aRealEngineOverSQLite(ctx)
	deletingAUserWithForeignKeysOff(ctx)
	timestampsAreFixedWidthText(ctx)
	theUpsertAndTheSecondFactorGate(ctx)
	singleUseThingsAreSingleUse(ctx)
	anomalyAndStuffingCounts(ctx)
	theReadOnlyQuerySurface(ctx)
	theSharedCacheTrap(ctx)

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
		return
	}
	fmt.Printf("%d CHECK(S) FAILED\n", failures)
	os.Exit(1)
}

// newDB opens and migrates a fresh database file. dsnSuffix is appended
// verbatim, so a scenario can ask for the wrong pragmas on purpose.
func newDB(ctx context.Context, dsnSuffix string) (*sql.DB, string, error) {
	dbSeq++
	path := filepath.Join(tempDir, fmt.Sprintf("cryden-%d.db", dbSeq))
	db, err := sql.Open("sqlite", "file:"+path+dsnSuffix)
	if err != nil {
		return nil, "", err
	}
	if err := sqlite.Migrate(ctx, db); err != nil {
		db.Close()
		return nil, "", err
	}
	return db, path, nil
}

// —————————————————————————————————————————————————————————————————————

func schemaAndPragmas(ctx context.Context) {
	section("the schema applies once and the pragmas are checkable")

	db, _, err := newDB(ctx, goodPragmas)
	if err != nil {
		fail(fmt.Sprintf("migrating a fresh database: %v", err))
		return
	}
	defer db.Close()
	pass("Migrate applied the schema to an empty file")

	check("CheckPragmas accepts a DSN that sets both", sqlite.CheckPragmas(ctx, db))

	for _, table := range []string{
		"users", "sessions", "audit_events", "verification_tokens",
		"oauth_identities", "totp_secrets", "webauthn_credentials",
		"recovery_codes", "login_attempts", "cryden_schema_migrations",
	} {
		var name string
		err := db.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
		check("table "+table+" exists", err)
	}

	// The partial indexes are why login_attempts is its own table rather
	// than more audit_events queries, so their presence is asserted.
	for _, index := range []string{
		"idx_sessions_user_active",
		"idx_login_attempts_user_failures",
		"idx_login_attempts_ip_failures",
		"idx_login_attempts_user_successes",
	} {
		var ddl string
		if err := db.QueryRowContext(ctx,
			`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?`, index).Scan(&ddl); err != nil {
			fail(fmt.Sprintf("index %s missing: %v", index, err))
			continue
		}
		if !contains(ddl, "WHERE") {
			fail(fmt.Sprintf("index %s is not partial: %s", index, ddl))
			continue
		}
		pass("partial index " + index + " exists")
	}

	check("Migrate is idempotent (second call)", sqlite.Migrate(ctx, db))
	check("Migrate is idempotent (third call)", sqlite.Migrate(ctx, db))
	var applied int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cryden_schema_migrations`).Scan(&applied); err != nil {
		fail(fmt.Sprintf("counting applied migrations: %v", err))
	} else {
		expectCount("exactly one migration is recorded after three calls", applied, 1)
	}

	// Negative: the DSN a host writes by accident. Both pragmas default
	// to off/zero, and CheckPragmas has to say so about both at once
	// rather than stopping at the first.
	bare, _, err := newDB(ctx, "")
	if err != nil {
		fail(fmt.Sprintf("opening a bare DSN: %v", err))
		return
	}
	defer bare.Close()
	bareErr := sqlite.CheckPragmas(ctx, bare)
	expectError("CheckPragmas rejects a DSN with no pragmas", bareErr)
	expectIs("and names the foreign-keys problem", bareErr, sqlite.ErrForeignKeysDisabled)
	expectIs("and the busy-timeout problem, in the same error", bareErr, sqlite.ErrNoBusyTimeout)
}

// —————————————————————————————————————————————————————————————————————

// engineOver wires a full engine to a set of SQLite stores over one
// database, which is the actual claim item 13 makes: the interfaces
// already exist, so a second backend needs no engine change at all.
func engineOver(db *sql.DB) (*cryden.Engine, error) {
	return cryden.New(cryden.Config{
		JWTSecret:     "smoke-test-secret-long-enough-to-be-plausible",
		EncryptionKey: "smoketest-encryption-key", // deliberately different from JWTSecret
		Users:         sqlite.NewUserStore(db),
		Sessions:      sqlite.NewSessionStore(db),
		Audit:         sqlite.NewAuditStore(db),
		Verifications: sqlite.NewVerificationStore(db),
		OAuth:         sqlite.NewOAuthStore(db),
		TOTP:          sqlite.NewTOTPStore(db),
		RecoveryCodes: sqlite.NewRecoveryCodeStore(db),
		Anomalies:     sqlite.NewAnomalyStore(db),
		// Several logins from one address in a row is the shape of this
		// test, not an attack.
		RateLimitAttempts: 1000,
		// The cheapest bcrypt this test can ask for: nothing here is
		// measuring the hasher.
		BcryptCost: 4,
	})
}

func aRealEngineOverSQLite(ctx context.Context) {
	section("a real engine runs end to end over sqlite, unmodified")

	db, _, err := newDB(ctx, goodPragmas)
	if err != nil {
		fail(fmt.Sprintf("migrating: %v", err))
		return
	}
	defer db.Close()

	engine, err := engineOver(db)
	if err != nil {
		fail(fmt.Sprintf("building the engine: %v", err))
		return
	}
	pass("cryden.New accepted a config of nothing but sqlite stores")

	user, err := cryden.SignUp(ctx, engine, email, password, homeIP)
	check("signed up", err)
	if err != nil {
		return
	}
	if user.ID == "" {
		fail("SignUp returned a user with no ID")
	} else {
		pass("the store assigned a user ID")
	}

	// Negative: the same address twice. Enforced by the UNIQUE index in
	// the migration, not by anything in Go.
	_, err = cryden.SignUp(ctx, engine, email, password, homeIP)
	expectError("signing up the same address twice is refused", err)

	// Negative: the wrong password, before the right one, so a failure
	// row exists for the anomaly counts to have found later.
	_, err = cryden.Login(ctx, engine, email, "wrong-"+password, homeIP, firefoxLinux)
	expectError("the wrong password is refused", err)

	tokens, err := cryden.Login(ctx, engine, email, password, homeIP, firefoxLinux)
	check("logged in", err)
	if err != nil {
		return
	}

	subject, err := cryden.VerifyToken(engine, tokens.AccessToken)
	check("the access token verifies", err)
	expectString("and carries the right subject", subject, user.ID)

	rotated, err := cryden.RefreshToken(ctx, engine, tokens.RefreshToken)
	check("the refresh token rotates", err)
	if err == nil && rotated.RefreshToken == tokens.RefreshToken {
		fail("rotation returned the same refresh token")
	} else if err == nil {
		pass("and the new refresh token differs from the old one")
	}

	// Negative: the retired token. Reuse detection reads the row the
	// rotation left behind, which is the part that had to survive
	// RETURNING not existing here.
	_, err = cryden.RefreshToken(ctx, engine, tokens.RefreshToken)
	expectError("replaying the retired refresh token is refused", err)

	// The whole family goes down on reuse, so the rotated token is gone
	// too — that is the designed response, not a bug in the backend.
	_, err = cryden.RefreshToken(ctx, engine, rotated.RefreshToken)
	expectError("and the reuse took the rest of the family with it", err)

	if _, err := cryden.Login(ctx, engine, email, password, officeIP, firefoxLinux); err != nil {
		fail(fmt.Sprintf("logging in a second time: %v", err))
		return
	}
	sessions, err := cryden.ListSessions(ctx, engine, user.ID)
	check("listing sessions", err)
	expectCount("one live session is listed", len(sessions), 1)

	if len(sessions) == 1 {
		check("revoking it", cryden.RevokeSession(ctx, engine, sessions[0].ID, user.ID))
		again, err := cryden.ListSessions(ctx, engine, user.ID)
		check("listing again", err)
		expectCount("and nothing is live any more", len(again), 0)
		// Negative: revoking twice. Postgres reports no rows affected
		// here and so does this, via the same explicit row count.
		expectIsError("revoking the same session twice is ErrNotFound",
			cryden.RevokeSession(ctx, engine, sessions[0].ID, user.ID), store.ErrNotFound)
	}

	// The audit trail is a real table with real rows, not a side channel.
	var events int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE user_id = ?`, user.ID).Scan(&events); err != nil {
		fail(fmt.Sprintf("counting audit events: %v", err))
	} else if events == 0 {
		fail("nothing was written to audit_events")
	} else {
		pass(fmt.Sprintf("audit_events holds %d rows for the account", events))
	}
}

// —————————————————————————————————————————————————————————————————————

// The security-critical one. SQLite honours ON DELETE CASCADE only when
// foreign_keys is on, and it is OFF by default, per connection, settable
// only from the DSN. A host that forgets it would otherwise get a
// deleted account whose session rows survive — refresh tokens that keep
// rotating for a user who no longer exists. So this scenario runs in
// exactly that configuration, deliberately.
func deletingAUserWithForeignKeysOff(ctx context.Context) {
	section("deleting a user cascades by hand, with foreign keys OFF")

	db, _, err := newDB(ctx, "") // no pragmas at all: SQLite's own defaults
	if err != nil {
		fail(fmt.Sprintf("migrating: %v", err))
		return
	}
	defer db.Close()

	var fk int
	if err := db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil {
		fail(fmt.Sprintf("reading the foreign_keys pragma: %v", err))
		return
	}
	expectCount("foreign_keys really is off in this scenario", fk, 0)

	users := sqlite.NewUserStore(db)
	sessions := sqlite.NewSessionStore(db)
	audit := sqlite.NewAuditStore(db)
	anomalies := sqlite.NewAnomalyStore(db)
	totp := sqlite.NewTOTPStore(db)
	codes := sqlite.NewRecoveryCodeStore(db)
	oauth := sqlite.NewOAuthStore(db)
	verifications := sqlite.NewVerificationStore(db)

	mustUser := func(id, addr string) {
		if err := users.Create(ctx, store.User{ID: id, Email: addr, PasswordHash: "$2a$04$placeholder"}); err != nil {
			fail(fmt.Sprintf("seeding %s: %v", id, err))
		}
	}
	mustUser("doomed", email)
	mustUser("bystander", "bystander@dev.com")

	seed := func(what string, err error) {
		if err != nil {
			fail(fmt.Sprintf("seeding %s: %v", what, err))
		}
	}
	seed("a session", sessions.Create(ctx, store.Session{
		ID: "sess-doomed", FamilyID: "sess-doomed", UserID: "doomed",
		TokenHash: "hash-doomed", IP: homeIP, UserAgent: firefoxLinux,
	}))
	seed("the bystander's session", sessions.Create(ctx, store.Session{
		ID: "sess-bystander", FamilyID: "sess-bystander", UserID: "bystander",
		TokenHash: "hash-bystander", IP: officeIP, UserAgent: firefoxLinux,
	}))
	seed("a verification token", verifications.Create(ctx, store.VerificationToken{
		ID: "vt-1", UserID: "doomed", Purpose: store.PurposeEmailVerify,
		TokenHash: "vt-hash", ExpiresAt: time.Now().Add(time.Hour),
	}))
	seed("an oauth identity", oauth.Link(ctx, store.OAuthIdentity{
		UserID: "doomed", Provider: "github", ExternalID: "gh-1", Email: email,
	}))
	seed("a totp secret", totp.Upsert(ctx, store.TOTPSecret{UserID: "doomed", EncryptedSecret: "secret"}))
	seed("recovery codes", codes.ReplaceAll(ctx, "doomed", []store.RecoveryCode{
		{UserID: "doomed", CodeHash: "rc-1"}, {UserID: "doomed", CodeHash: "rc-2"},
	}))
	seed("an audit event", audit.Record(ctx, store.AuditEvent{
		Type: store.EventLoginSuccess, UserID: "doomed", IP: homeIP,
	}))
	seed("a login attempt", anomalies.RecordAttempt(ctx, store.LoginAttempt{
		UserID: "doomed", IP: homeIP, Outcome: store.OutcomeSuccess,
	}))
	pass("seeded every table that references a user")

	check("deleted the user", users.Delete(ctx, "doomed"))

	// Children that CASCADE in the schema must be gone even though the
	// database was never told to enforce that.
	for _, table := range []string{
		"sessions", "verification_tokens", "oauth_identities",
		"totp_secrets", "recovery_codes", "webauthn_credentials",
	} {
		var n int
		if err := db.QueryRowContext(ctx,
			fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE user_id = ?`, table), "doomed").Scan(&n); err != nil {
			fail(fmt.Sprintf("counting %s: %v", table, err))
			continue
		}
		expectCount(table+" kept nothing for the deleted user", n, 0)
	}

	// The two that SET NULL keep their row: the security record of what
	// happened outlives the account it happened to.
	for _, table := range []string{"audit_events", "login_attempts"} {
		var total, detached int
		if err := db.QueryRowContext(ctx,
			fmt.Sprintf(`SELECT COUNT(*), COUNT(CASE WHEN user_id IS NULL THEN 1 END) FROM %s`, table)).Scan(&total, &detached); err != nil {
			fail(fmt.Sprintf("counting %s: %v", table, err))
			continue
		}
		expectCount(table+" still holds its row", total, 1)
		expectCount("and that row's user_id was NULLed, not deleted", detached, 1)
	}

	// And the blast radius stopped at the account it was aimed at.
	var bystanderSessions int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sessions WHERE user_id = ?`, "bystander").Scan(&bystanderSessions); err != nil {
		fail(fmt.Sprintf("counting the bystander's sessions: %v", err))
	} else {
		expectCount("another account's session is untouched", bystanderSessions, 1)
	}
	if _, err := users.GetByID(ctx, "bystander"); err != nil {
		fail(fmt.Sprintf("the bystander's own row: %v", err))
	} else {
		pass("and their user row is still there")
	}

	// Negative: deleting what is not there.
	expectIsError("deleting a user that does not exist is ErrNotFound",
		users.Delete(ctx, "never-existed"), store.ErrNotFound)
}

// —————————————————————————————————————————————————————————————————————

// Every "most recent" query in the package is a string comparison. That
// only agrees with chronology because the stored format is fixed-width,
// which is the reason time.RFC3339Nano — which trims trailing zeros —
// is not what anything here writes with.
func timestampsAreFixedWidthText(ctx context.Context) {
	section("timestamps are fixed-width TEXT, so string order is time order")

	db, _, err := newDB(ctx, goodPragmas)
	if err != nil {
		fail(fmt.Sprintf("migrating: %v", err))
		return
	}
	defer db.Close()

	users := sqlite.NewUserStore(db)
	if err := users.Create(ctx, store.User{ID: "user-1", Email: email, PasswordHash: "$2a$04$placeholder"}); err != nil {
		fail(fmt.Sprintf("seeding: %v", err))
		return
	}

	// A fractional part whose trailing zeros a trimming format would
	// have dropped, taking the fixed width with them.
	when := time.Date(2026, 9, 5, 12, 34, 56, 100000000, time.UTC)
	check("locked an account until a time with trailing zeros", users.LockAccount(ctx, "user-1", when))

	var raw string
	if err := db.QueryRowContext(ctx, `SELECT locked_until FROM users WHERE id = ?`, "user-1").Scan(&raw); err != nil {
		fail(fmt.Sprintf("reading the raw column: %v", err))
		return
	}
	expectString("the column holds the zero-padded form", raw, "2026-09-05T12:34:56.100000000Z")
	expectCount("which is a fixed 30 characters wide", len(raw), 30)

	back, err := users.GetByID(ctx, "user-1")
	check("read the user back", err)
	if err == nil {
		if back.LockedUntil == nil || !back.LockedUntil.Equal(when) {
			fail(fmt.Sprintf("locked_until round-tripped as %v, want %v", back.LockedUntil, when))
		} else {
			pass("and the instant survived to the nanosecond")
		}
	}

	// Rows written deliberately out of chronological order. If the format
	// were not fixed-width, ORDER BY created_at DESC would disagree with
	// time and every newest-first listing in the package would be wrong.
	sessions := sqlite.NewSessionStore(db)
	for i, s := range []store.Session{
		{ID: "s-1", FamilyID: "s-1", UserID: "user-1", TokenHash: "h-1", IP: homeIP},
		{ID: "s-2", FamilyID: "s-2", UserID: "user-1", TokenHash: "h-2", IP: homeIP},
		{ID: "s-3", FamilyID: "s-3", UserID: "user-1", TokenHash: "h-3", IP: homeIP},
	} {
		if err := sessions.Create(ctx, s); err != nil {
			fail(fmt.Sprintf("creating session %d: %v", i, err))
			return
		}
		// Enough to separate the rows at the second boundary crossings a
		// trimming format would mangle, without slowing the run down.
		time.Sleep(2 * time.Millisecond)
	}
	listed, err := sessions.ListByUser(ctx, "user-1")
	check("listed the sessions", err)
	expectCount("all three came back", len(listed), 3)
	if len(listed) == 3 {
		ordered := true
		for i := 1; i < len(listed); i++ {
			if listed[i].CreatedAt.After(listed[i-1].CreatedAt) {
				ordered = false
			}
		}
		if ordered {
			pass("newest first, by string comparison on the TEXT column")
		} else {
			fail("newest-first ordering is broken")
		}
		expectString("and the newest really is the last one written", listed[0].ID, "s-3")
	}

	// The columns are declared TEXT rather than DATETIME on purpose: a
	// driver that sees a DATETIME declaration may hand back a time.Time
	// instead of a string, which would break every scan in the package.
	for _, col := range []struct{ table, column string }{
		{"users", "created_at"},
		{"users", "locked_until"},
		{"sessions", "created_at"},
		{"audit_events", "created_at"},
		{"login_attempts", "created_at"},
		{"verification_tokens", "expires_at"},
	} {
		var declared string
		err := db.QueryRowContext(ctx,
			`SELECT type FROM pragma_table_info(?) WHERE name = ?`, col.table, col.column).Scan(&declared)
		if err != nil {
			fail(fmt.Sprintf("reading %s.%s's declared type: %v", col.table, col.column, err))
			continue
		}
		expectString(fmt.Sprintf("%s.%s is declared TEXT, not DATETIME", col.table, col.column), declared, "TEXT")
	}
}

// —————————————————————————————————————————————————————————————————————

// ON CONFLICT ... DO UPDATE is the one Postgres-ism that needed no
// translation — SQLite has had it since 3.24 (2018). What it does here
// is security-relevant, not just idempotent: re-enrolling produces a new
// secret, and the confirmation that proved possession of the old one
// says nothing about this one.
func theUpsertAndTheSecondFactorGate(ctx context.Context) {
	section("re-enrolling TOTP replaces the secret and clears its confirmation")

	db, _, err := newDB(ctx, goodPragmas)
	if err != nil {
		fail(fmt.Sprintf("migrating: %v", err))
		return
	}
	defer db.Close()

	engine, err := engineOver(db)
	if err != nil {
		fail(fmt.Sprintf("building the engine: %v", err))
		return
	}
	user, err := cryden.SignUp(ctx, engine, email, password, homeIP)
	if err != nil {
		fail(fmt.Sprintf("signing up: %v", err))
		return
	}

	totp := sqlite.NewTOTPStore(db)
	check("enrolled a secret", totp.Upsert(ctx, store.TOTPSecret{UserID: user.ID, EncryptedSecret: "first-secret"}))
	check("confirmed it", totp.Confirm(ctx, user.ID))

	got, err := totp.GetByUserID(ctx, user.ID)
	check("read it back", err)
	if err == nil {
		expectString("the secret is the one stored", got.EncryptedSecret, "first-secret")
		if got.ConfirmedAt == nil {
			fail("confirmed_at is still NULL after Confirm")
		} else {
			pass("and it is marked confirmed")
		}
	}

	// A confirmed secret is what makes Login pause instead of issuing
	// tokens — the gate reads this store, so this is the check that the
	// backend's ConfirmedAt actually reaches the auth path.
	_, err = cryden.Login(ctx, engine, email, password, homeIP, firefoxLinux)
	var pending *auth.ErrSecondFactorRequired
	if errors.As(err, &pending) {
		pass("logging in now pauses for a second factor")
		if len(pending.Methods) == 1 && pending.Methods[0] == "totp" {
			pass("and offers exactly the method that is enrolled")
		} else {
			fail(fmt.Sprintf("offered methods %v, want just totp", pending.Methods))
		}
	} else {
		fail(fmt.Sprintf("expected *ErrSecondFactorRequired, got %v", err))
	}

	check("re-enrolled with a different secret", totp.Upsert(ctx, store.TOTPSecret{UserID: user.ID, EncryptedSecret: "second-secret"}))
	got, err = totp.GetByUserID(ctx, user.ID)
	check("read it back again", err)
	if err == nil {
		expectString("the new secret replaced the old one", got.EncryptedSecret, "second-secret")
		if got.ConfirmedAt != nil {
			fail("confirmed_at survived a re-enrolment — an unverified secret could gate logins")
		} else {
			pass("and the confirmation was cleared, as it must be")
		}
	}

	var rows int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM totp_secrets WHERE user_id = ?`, user.ID).Scan(&rows); err != nil {
		fail(fmt.Sprintf("counting secrets: %v", err))
	} else {
		expectCount("the upsert updated a row rather than adding one", rows, 1)
	}

	// An unconfirmed secret is not a second factor, so the gate reopens.
	_, err = cryden.Login(ctx, engine, email, password, homeIP, firefoxLinux)
	check("and logging in issues tokens again", err)

	// Negative: confirming or deleting a secret nobody enrolled.
	expectIsError("confirming a secret that does not exist is ErrNotFound",
		totp.Confirm(ctx, "no-such-user"), store.ErrNotFound)
	expectIsError("deleting one that does not exist is ErrNotFound",
		totp.Delete(ctx, "no-such-user"), store.ErrNotFound)
}

// —————————————————————————————————————————————————————————————————————

// Every single-use thing in the schema is enforced with an explicit
// "AND used_at IS NULL" plus a row count, because SQLite has no
// RETURNING to lean on below 3.35 and plenty of long-term distributions
// ship older. If any of these consumed twice, a stolen token or a leaked
// recovery code would be reusable.
func singleUseThingsAreSingleUse(ctx context.Context) {
	section("single-use rows really are single-use")

	db, _, err := newDB(ctx, goodPragmas)
	if err != nil {
		fail(fmt.Sprintf("migrating: %v", err))
		return
	}
	defer db.Close()

	users := sqlite.NewUserStore(db)
	if err := users.Create(ctx, store.User{ID: "user-1", Email: email, PasswordHash: "$2a$04$placeholder"}); err != nil {
		fail(fmt.Sprintf("seeding: %v", err))
		return
	}

	verifications := sqlite.NewVerificationStore(db)
	check("created a verification token", verifications.Create(ctx, store.VerificationToken{
		ID: "vt-1", UserID: "user-1", Purpose: store.PurposeMagicLink,
		TokenHash: "vt-hash", ExpiresAt: time.Now().Add(time.Hour),
	}))
	vt, err := verifications.GetByTokenHash(ctx, "vt-hash")
	check("looked it up by hash", err)
	if err == nil {
		expectString("and got the right row", vt.ID, "vt-1")
	}
	check("marked it used", verifications.MarkUsed(ctx, "vt-1"))
	expectIsError("marking it used a second time is ErrNotFound",
		verifications.MarkUsed(ctx, "vt-1"), store.ErrNotFound)

	// An expired token still comes back from the lookup on purpose: the
	// caller decides what expiry means, and a lookup that hid them would
	// report "no such token" for a token that exists.
	check("created an already-expired token", verifications.Create(ctx, store.VerificationToken{
		ID: "vt-2", UserID: "user-1", Purpose: store.PurposeMagicLink,
		TokenHash: "vt-hash-2", ExpiresAt: time.Now().Add(-time.Hour),
	}))
	if _, err := verifications.GetByTokenHash(ctx, "vt-hash-2"); err != nil {
		fail(fmt.Sprintf("an expired token should still be returned: %v", err))
	} else {
		pass("an expired token is still returned, for the caller to judge")
	}
	expectIsError("a hash nobody stored is ErrNotFound",
		errOf(verifications.GetByTokenHash(ctx, "never-issued")), store.ErrNotFound)

	codes := sqlite.NewRecoveryCodeStore(db)
	check("stored a batch of recovery codes", codes.ReplaceAll(ctx, "user-1", []store.RecoveryCode{
		{UserID: "user-1", CodeHash: "rc-1"},
		{UserID: "user-1", CodeHash: "rc-2"},
		{UserID: "user-1", CodeHash: "rc-3"},
	}))
	if n, err := codes.CountUnused(ctx, "user-1"); err != nil {
		fail(fmt.Sprintf("CountUnused: %v", err))
	} else {
		expectCount("three are unused", n, 3)
	}
	check("consumed one", codes.Consume(ctx, "user-1", "rc-1"))
	if n, err := codes.CountUnused(ctx, "user-1"); err != nil {
		fail(fmt.Sprintf("CountUnused: %v", err))
	} else {
		expectCount("two are left", n, 2)
	}
	expectIsError("consuming the same code twice is ErrNotFound",
		codes.Consume(ctx, "user-1", "rc-1"), store.ErrNotFound)
	expectIsError("a code that was never issued is ErrNotFound",
		codes.Consume(ctx, "user-1", "rc-nonsense"), store.ErrNotFound)

	// Regenerating invalidates the whole previous batch — there is no
	// incremental add, so a leaked sheet is dead the moment a new one is
	// printed.
	check("regenerated the batch", codes.ReplaceAll(ctx, "user-1", []store.RecoveryCode{
		{UserID: "user-1", CodeHash: "rc-new"},
	}))
	if n, err := codes.CountUnused(ctx, "user-1"); err != nil {
		fail(fmt.Sprintf("CountUnused: %v", err))
	} else {
		expectCount("only the new code is unused", n, 1)
	}
	expectIsError("a code from the previous batch no longer works",
		codes.Consume(ctx, "user-1", "rc-2"), store.ErrNotFound)

	sessions := sqlite.NewSessionStore(db)
	if err := sessions.Create(ctx, store.Session{
		ID: "s-1", FamilyID: "s-1", UserID: "user-1", TokenHash: token.HashToken("raw-refresh"), IP: homeIP,
	}); err != nil {
		fail(fmt.Sprintf("creating a session: %v", err))
		return
	}
	// A revoked session is still findable by design: a lookup that hid it
	// would turn a replay attack into a plain "not found", and reuse
	// detection needs the row.
	check("revoked it", sessions.Revoke(ctx, "s-1"))
	if _, err := sessions.GetByTokenHash(ctx, token.HashToken("raw-refresh")); err != nil {
		fail(fmt.Sprintf("a revoked session must still be findable: %v", err))
	} else {
		pass("and it is still findable, so a replay is detectable")
	}
	expectIsError("revoking it again is ErrNotFound",
		sessions.Revoke(ctx, "s-1"), store.ErrNotFound)
}

// —————————————————————————————————————————————————————————————————————

// The two velocity counts and the credential-stuffing breadth query, the
// last of which is where Postgres's COUNT(*) FILTER (WHERE ...) had to
// become the older COUNT(CASE WHEN ...) form so the query still runs on
// the 3.24-era builds long-term distributions ship.
func anomalyAndStuffingCounts(ctx context.Context) {
	section("the anomaly and credential-stuffing queries count the right things")

	db, _, err := newDB(ctx, goodPragmas)
	if err != nil {
		fail(fmt.Sprintf("migrating: %v", err))
		return
	}
	defer db.Close()

	users := sqlite.NewUserStore(db)
	for i, addr := range []string{email, "second@dev.com", "third@dev.com"} {
		if err := users.Create(ctx, store.User{
			ID: fmt.Sprintf("user-%d", i+1), Email: addr, PasswordHash: "$2a$04$placeholder",
		}); err != nil {
			fail(fmt.Sprintf("seeding user %d: %v", i+1, err))
			return
		}
	}

	anomalies := sqlite.NewAnomalyStore(db)
	record := func(userID, ip string, outcome store.LoginAttemptOutcome) {
		if err := anomalies.RecordAttempt(ctx, store.LoginAttempt{
			UserID: userID, IP: ip, UserAgent: firefoxLinux, Outcome: outcome,
		}); err != nil {
			fail(fmt.Sprintf("recording an attempt: %v", err))
		}
	}

	// A known-good history for user-1, then a spray from one address
	// against three accounts plus four addresses with no account at all.
	record("user-1", homeIP, store.OutcomeSuccess)
	time.Sleep(2 * time.Millisecond)
	record("user-1", officeIP, store.OutcomeSuccess)
	record("user-1", attackIP, store.OutcomeFailure)
	record("user-2", attackIP, store.OutcomeFailure)
	record("user-2", attackIP, store.OutcomeFailure)
	record("user-3", attackIP, store.OutcomeFailure)
	for i := 0; i < 4; i++ {
		record("", attackIP, store.OutcomeFailure)
	}
	pass("recorded a baseline plus a spray from one address")

	baseline, err := anomalies.ListRecentSuccesses(ctx, "user-1", 10)
	check("listed the account's recent successes", err)
	expectCount("only the successes came back", len(baseline), 2)
	if len(baseline) == 2 {
		expectString("newest first", baseline[0].IP, officeIP)
		if baseline[0].ID == "" || baseline[0].CreatedAt.IsZero() {
			fail("the store did not assign an ID and a timestamp")
		} else {
			pass("and the store assigned each row an ID and a timestamp")
		}
	}

	since := time.Now().Add(-time.Minute)
	if n, err := anomalies.CountFailuresForUser(ctx, "user-1", since); err != nil {
		fail(fmt.Sprintf("CountFailuresForUser: %v", err))
	} else {
		expectCount("one failure counted against user-1", n, 1)
	}
	if n, err := anomalies.CountFailuresForIP(ctx, attackIP, since); err != nil {
		fail(fmt.Sprintf("CountFailuresForIP: %v", err))
	} else {
		expectCount("eight failures counted against the attacking address", n, 8)
	}

	counts, err := anomalies.CountTargetsForIP(ctx, attackIP, since)
	check("counted the address's targets", err)
	expectCount("three distinct known accounts, not the six attempts", counts.DistinctAccounts, 3)
	expectCount("four unknown-target failures, counted per attempt", counts.UnknownTargetFailures, 4)

	// Negative: an address that did nothing. COUNT, not SUM — over zero
	// rows COUNT is 0, whereas SUM is NULL and would not scan into an int.
	quiet, err := anomalies.CountTargetsForIP(ctx, "192.0.2.1", since)
	check("counting an address with no history at all", err)
	if quiet != (store.IPTargetCounts{}) {
		fail(fmt.Sprintf("an unseen address returned %+v, want zeroes", quiet))
	} else {
		pass("and it returns zeroes rather than failing to scan a NULL")
	}

	// Negative: a window that opens after everything happened.
	future := time.Now().Add(time.Minute)
	if n, err := anomalies.CountFailuresForIP(ctx, attackIP, future); err != nil || n != 0 {
		fail(fmt.Sprintf("a future window returned %d (err %v), want 0", n, err))
	} else {
		pass("a window that starts in the future sees nothing")
	}

	// Negative: empty identifiers short-circuit instead of matching
	// whatever rows happen to have an empty column.
	if n, err := anomalies.CountFailuresForUser(ctx, "", since); err != nil || n != 0 {
		fail(fmt.Sprintf("an empty user id returned %d (err %v), want 0", n, err))
	} else {
		pass("an empty user id counts nothing")
	}
	if n, err := anomalies.CountFailuresForIP(ctx, "", since); err != nil || n != 0 {
		fail(fmt.Sprintf("an empty address returned %d (err %v), want 0", n, err))
	} else {
		pass("an empty address counts nothing")
	}

	// One account hammered many times is per-account lockout's problem,
	// not stuffing's: breadth must stay at one however high volume goes.
	for i := 0; i < 12; i++ {
		record("user-1", "198.51.100.99", store.OutcomeFailure)
	}
	hammered, err := anomalies.CountTargetsForIP(ctx, "198.51.100.99", since)
	check("counted an address hammering a single account", err)
	expectCount("breadth stays at one account", hammered.DistinctAccounts, 1)
	if n, err := anomalies.CountFailuresForIP(ctx, "198.51.100.99", since); err != nil || n != 12 {
		fail(fmt.Sprintf("volume returned %d (err %v), want all 12", n, err))
	} else {
		pass("while the volume is still fully visible")
	}
}

// —————————————————————————————————————————————————————————————————————

// The AI query surface. In store/postgres the safety boundary is a
// read-only role; here it is a second handle on the same file opened
// with mode=ro. Allowlist validation sits on top of that, not instead of
// it — so both halves are checked, and the read-only half is checked by
// trying to write.
func theReadOnlyQuerySurface(ctx context.Context) {
	section("the AI query surface reads through a read-only handle")

	db, path, err := newDB(ctx, goodPragmas)
	if err != nil {
		fail(fmt.Sprintf("migrating: %v", err))
		return
	}
	defer db.Close()

	users := sqlite.NewUserStore(db)
	sessions := sqlite.NewSessionStore(db)
	audit := sqlite.NewAuditStore(db)
	for i, u := range []struct {
		id, addr string
	}{{"user-1", email}, {"user-2", "raymond.other@dev.com"}, {"user-3", "someoneelse@example.org"}} {
		if err := users.Create(ctx, store.User{
			ID: u.id, Email: u.addr,
			PasswordHash: fmt.Sprintf("$2a$04$this-hash-must-never-be-queryable-%d", i),
		}); err != nil {
			fail(fmt.Sprintf("seeding %s: %v", u.id, err))
			return
		}
	}
	for _, s := range []store.Session{
		{ID: "s-1", FamilyID: "s-1", UserID: "user-1", TokenHash: "secret-hash-1", IP: homeIP, UserAgent: firefoxLinux},
		{ID: "s-2", FamilyID: "s-2", UserID: "user-2", TokenHash: "secret-hash-2", IP: homeIP, UserAgent: firefoxLinux},
	} {
		if err := sessions.Create(ctx, s); err != nil {
			fail(fmt.Sprintf("seeding %s: %v", s.ID, err))
			return
		}
	}
	for _, e := range []store.AuditEvent{
		{Type: store.EventLoginSuccess, UserID: "user-1", IP: homeIP},
		{Type: store.EventLoginFailed, UserID: "user-2", IP: attackIP},
		{Type: store.EventLoginFailed, IP: attackIP},
	} {
		if err := audit.Record(ctx, e); err != nil {
			fail(fmt.Sprintf("seeding an audit event: %v", err))
			return
		}
	}
	pass("seeded three accounts, two sessions and three audit events")

	// The handle the store's doc comment insists on: same file, mode=ro.
	ro, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		fail(fmt.Sprintf("opening the file read-only: %v", err))
		return
	}
	defer ro.Close()
	queries := sqlite.NewSafeQueryStore(ro)
	pass("opened a second, read-only handle on the same file")

	result, err := queries.RunSafeQuery(ctx, ai.QueryIntent{Entity: "users"})
	check("a plain listing works through it", err)
	expectCount("all three accounts came back", len(result.Rows), 3)
	if len(result.Columns) > 0 {
		leaked := false
		for _, c := range result.Columns {
			if c == "password_hash" || c == "token_hash" {
				leaked = true
			}
		}
		for _, row := range result.Rows {
			for _, cell := range row {
				if contains(cell, "must-never-be-queryable") {
					leaked = true
				}
			}
		}
		if leaked {
			fail("a hash reached the result")
		} else {
			pass("and no hash appears in the columns or the cells")
		}
	}

	filtered, err := queries.RunSafeQuery(ctx, ai.QueryIntent{
		Entity:  "users",
		Filters: []ai.QueryFilter{{Field: "email", Operator: "contains", Value: "raymond"}},
	})
	check("a contains filter works", err)
	expectCount("and matched the two addresses that contain it", len(filtered.Rows), 2)

	counted, err := queries.RunSafeQuery(ctx, ai.QueryIntent{Entity: "sessions", Aggregate: "count"})
	check("a count aggregate works", err)
	if len(counted.Rows) == 1 {
		expectString("and reports two sessions", counted.Rows[0][0], "2")
	} else {
		fail(fmt.Sprintf("count returned %d rows, want 1", len(counted.Rows)))
	}

	grouped, err := queries.RunSafeQuery(ctx, ai.QueryIntent{
		Entity: "audit_events", Aggregate: "group_by", GroupBy: "type",
	})
	check("a group_by aggregate works", err)
	if len(grouped.Rows) == 2 {
		expectString("busiest bucket first", grouped.Rows[0][0], string(store.EventLoginFailed))
		expectString("with the right count", grouped.Rows[0][1], "2")
	} else {
		fail(fmt.Sprintf("group_by returned %d buckets, want 2", len(grouped.Rows)))
	}

	// Negative: everything off the allowlist, each rejected before any
	// query is built.
	for _, tc := range []struct {
		what   string
		intent ai.QueryIntent
	}{
		{"a table that is not on the allowlist", ai.QueryIntent{Entity: "totp_secrets"}},
		{"an empty entity", ai.QueryIntent{Entity: ""}},
		{"SQL smuggled in as an entity", ai.QueryIntent{Entity: "users; DROP TABLE users"}},
		{"a filter on password_hash", ai.QueryIntent{
			Entity:  "users",
			Filters: []ai.QueryFilter{{Field: "password_hash", Operator: "=", Value: "x"}},
		}},
		{"a filter on token_hash", ai.QueryIntent{
			Entity:  "sessions",
			Filters: []ai.QueryFilter{{Field: "token_hash", Operator: "=", Value: "secret-hash-1"}},
		}},
		{"a field belonging to a different entity", ai.QueryIntent{
			Entity:  "users",
			Filters: []ai.QueryFilter{{Field: "user_agent", Operator: "=", Value: firefoxLinux}},
		}},
		{"an operator that is not allowlisted", ai.QueryIntent{
			Entity:  "users",
			Filters: []ai.QueryFilter{{Field: "email", Operator: "!=", Value: email}},
		}},
		{"SQL smuggled in as an operator", ai.QueryIntent{
			Entity:  "users",
			Filters: []ai.QueryFilter{{Field: "email", Operator: "= '' OR 1=1 --", Value: "x"}},
		}},
		{"grouping by password_hash", ai.QueryIntent{
			Entity: "users", Aggregate: "group_by", GroupBy: "password_hash",
		}},
		{"grouping by nothing at all", ai.QueryIntent{
			Entity: "users", Aggregate: "group_by", GroupBy: "",
		}},
	} {
		_, err := queries.RunSafeQuery(ctx, tc.intent)
		expectError("rejected: "+tc.what, err)
	}

	// A value shaped like an injection is bound, not interpolated, so it
	// simply matches nothing.
	inert, err := queries.RunSafeQuery(ctx, ai.QueryIntent{
		Entity:  "users",
		Filters: []ai.QueryFilter{{Field: "email", Operator: "=", Value: "' OR 1=1; DROP TABLE users; --"}},
	})
	check("an injection-shaped value is accepted as a value", err)
	expectCount("and matches nothing", len(inert.Rows), 0)

	// Negative, and the real point: the handle itself cannot write. This
	// is what makes the allowlist defense-in-depth rather than the only
	// thing standing between a hallucinated intent and the data.
	for _, stmt := range []string{
		`DELETE FROM users`,
		`UPDATE users SET email = 'attacker@dev.com'`,
		`DROP TABLE sessions`,
	} {
		if _, err := ro.ExecContext(ctx, stmt); err == nil {
			fail(fmt.Sprintf("%q succeeded on a mode=ro handle", stmt))
		} else {
			pass(fmt.Sprintf("the read-only handle refuses %s", firstWords(stmt)))
		}
	}

	var stillThere int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&stillThere); err != nil {
		fail(fmt.Sprintf("counting users afterwards: %v", err))
	} else {
		expectCount("and all three accounts are still there", stillThere, 3)
	}
}

// —————————————————————————————————————————————————————————————————————

// The trap a host adopting this backend is most likely to fall into, and
// the reason this smoke test uses files rather than memory like every
// other one here. A bare ":memory:" database belongs to a single
// connection, and *sql.DB is a pool that opens more whenever it likes —
// so the schema you migrated is on one connection and the next query
// lands on a different, empty database. It fails as "no such table",
// intermittently, under load. cache=shared is the fix.
func theSharedCacheTrap(ctx context.Context) {
	section("an in-memory DSN needs cache=shared to survive a pool")

	bare, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		fail(fmt.Sprintf("opening :memory:: %v", err))
		return
	}
	defer bare.Close()

	// Migrate on whichever connection the pool hands out first.
	if err := sqlite.Migrate(ctx, bare); err != nil {
		fail(fmt.Sprintf("migrating :memory:: %v", err))
		return
	}
	pass("migrated a bare :memory: database")

	// Hold that connection so the next query has to open a second one.
	held, err := bare.Conn(ctx)
	if err != nil {
		fail(fmt.Sprintf("taking a connection out of the pool: %v", err))
		return
	}
	defer held.Close()

	var name string
	err = bare.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE name = 'users'`).Scan(&name)
	if err == nil {
		fail("a second connection saw the schema — this DSN is not as isolated as documented")
	} else {
		pass("a second connection sees an empty database, as SQLite intends")
	}
	if err := held.Close(); err != nil {
		fail(fmt.Sprintf("releasing the held connection: %v", err))
	}

	// The same DSN with cache=shared, which is what a host testing
	// against this backend in memory actually wants.
	shared, err := sql.Open("sqlite", "file:smoketest-shared?mode=memory&cache=shared&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		fail(fmt.Sprintf("opening a shared-cache memory DSN: %v", err))
		return
	}
	defer shared.Close()
	check("migrated a cache=shared memory database", sqlite.Migrate(ctx, shared))

	held2, err := shared.Conn(ctx)
	if err != nil {
		fail(fmt.Sprintf("taking a connection out of the pool: %v", err))
		return
	}
	defer held2.Close()
	check("and a second connection finds the schema",
		shared.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE name = 'users'`).Scan(&name))
	if err := held2.Close(); err != nil {
		fail(fmt.Sprintf("releasing the held connection: %v", err))
	}

	// It is a real database, not a stub: the stores work over it.
	users := sqlite.NewUserStore(shared)
	check("a user round-trips through it", users.Create(ctx, store.User{
		ID: "user-1", Email: email, PasswordHash: "$2a$04$placeholder",
	}))
	if got, err := users.GetByEmail(ctx, email); err != nil {
		fail(fmt.Sprintf("GetByEmail: %v", err))
	} else {
		expectString("and reads back correctly", got.ID, "user-1")
	}
	expectIsError("while a missing account is still ErrNotFound",
		errOf(users.GetByEmail(ctx, "nobody@dev.com")), store.ErrNotFound)
}

// —————————————————————————————————————————————————————————————————————

func section(name string) {
	fmt.Printf("\n— %s\n", name)
}

// errOf discards a two-value call's first result, so a lookup's error can
// be handed straight to expectIsError.
func errOf[T any](_ T, err error) error { return err }

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// firstWords keeps a failure line short when the thing being reported is
// a whole SQL statement.
func firstWords(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			for j := i + 1; j < len(s); j++ {
				if s[j] == ' ' {
					return s[:j]
				}
			}
			return s
		}
	}
	return s
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

func expectError(step string, err error) {
	if err == nil {
		fail(step + ": expected an error, got none")
		return
	}
	pass(step)
}

func expectIs(step string, err, target error) {
	if !errors.Is(err, target) {
		fail(fmt.Sprintf("%s: %v does not wrap %v", step, err, target))
		return
	}
	pass(step)
}

func expectIsError(step string, err, target error) {
	if err == nil {
		fail(step + ": expected an error, got none")
		return
	}
	expectIs(step, err, target)
}

func check(step string, err error) {
	if err != nil {
		fail(fmt.Sprintf("%s: unexpected error: %v", step, err))
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
