# Manual test guide — the SQLite storage backend

Every `store.X` interface already existed. This item implements all of
them, plus `ai.QueryableStore`, against SQLite — so a host can run
cryden on a single file with no server, and nothing in `auth/`,
`session/`, `security/` or the facade changes or can tell which backend
it holds.

Three things about it are worth knowing before you test it, because they
are where a SQLite port stops being a syntax swap:

- **Pragmas live in the DSN, and two of them matter.** SQLite defaults
  `foreign_keys` to **off** and `busy_timeout` to **0**. Both are
  per-connection, and `*sql.DB` is a pool that opens connections
  whenever it likes, so the DSN is the only place that can set them for
  every connection. `sqlite.CheckPragmas` exists to tell you when you
  got it wrong.
- **Timestamps are fixed-width TEXT**, not `DATETIME`. Every
  "most recent" query in the package is a string comparison, and it only
  agrees with chronology because the format is zero-padded to exactly 30
  characters. The columns are declared `TEXT` on purpose too: some
  drivers convert a column *declared* `DATETIME` into a `time.Time`
  behind your back, which would break every scan in the package.
- **`UserStore.Delete` cascades by hand.** The schema declares
  `ON DELETE CASCADE`, but SQLite honours those only when the pragma
  above is on. A host that forgets it would otherwise get a deleted
  account whose session rows survive — refresh tokens that keep rotating
  for a user who no longer exists. That is a security hole, not a
  tidiness problem, so the cascade is written out in a transaction and
  correctness never depends on how you spelled your DSN.

The fastest full check is the smoke test:

```
go run ./cmd/smoketest/sqlite-store
```

160 checks over nine sections. It writes real database files under a
temporary directory and removes them at the end — unlike the other smoke
tests here, it is not purely in memory, because WAL, `busy_timeout` and
the read-only handle only mean anything on a file. What follows is the
same ground by hand.

## Setup

`store/sqlite` **imports no driver at all.** You pick one and register
it yourself; the engine never forces a choice, least of all on Postgres
users who will never load any of it. Three work:

| driver | cgo | notes |
| --- | --- | --- |
| `modernc.org/sqlite` | no | pure Go, works with `CGO_ENABLED=0`. What this repo's tests use. |
| `github.com/mattn/go-sqlite3` | yes | the long-standing cgo binding. |
| `github.com/ncruces/go-sqlite3` | no | WASM-based. |

The pragma **syntax differs between drivers**, which is the one place
your DSN is not portable:

```go
// modernc.org/sqlite
dsn := "file:cryden.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"

// mattn/go-sqlite3
dsn := "file:cryden.db?_foreign_keys=1&_busy_timeout=5000&_journal_mode=WAL"
```

Then wire it up. The store never opens or closes a database — you own
the handle's lifecycle, same as with Postgres:

```go
import (
    _ "modernc.org/sqlite" // or your driver of choice

    "github.com/crydensync/cryden/v2"
    "github.com/crydensync/cryden/v2/store/sqlite"
)

db, err := sql.Open("sqlite", dsn)
if err != nil {
    log.Fatal(err)
}
defer db.Close()

if err := sqlite.Migrate(ctx, db); err != nil {
    log.Fatal(err)
}
// Says out loud what a quiet default would let you ship: run it once at
// startup and refuse to start, or at least log loudly.
if err := sqlite.CheckPragmas(ctx, db); err != nil {
    log.Fatal(err)
}

engine, err := cryden.New(cryden.Config{
    JWTSecret:     os.Getenv("CRYDEN_JWT_SECRET"),
    EncryptionKey: os.Getenv("CRYDEN_ENCRYPTION_KEY"), // only if TOTP/WebAuthn is set
    Users:         sqlite.NewUserStore(db),
    Sessions:      sqlite.NewSessionStore(db),
    Audit:         sqlite.NewAuditStore(db),
    Verifications: sqlite.NewVerificationStore(db),
    OAuth:         sqlite.NewOAuthStore(db),
    TOTP:          sqlite.NewTOTPStore(db),
    WebAuthn:      sqlite.NewWebAuthnStore(db),
    RecoveryCodes: sqlite.NewRecoveryCodeStore(db),
    Anomalies:     sqlite.NewAnomalyStore(db),

    // Required together with WebAuthn, and unrelated to this item —
    // Config rejects the store without them.
    WebAuthnRPID:          "yourapp.com",
    WebAuthnRPDisplayName: "Your App",
    WebAuthnRPOrigins:     []string{"https://yourapp.com"},
})
```

One caveat on **write concurrency**: SQLite allows one writer at a time.
`busy_timeout` is what turns a contended write from an instant
`SQLITE_BUSY` error into a short wait, and WAL is what lets readers keep
reading during a write. Set both. If your host is write-heavy across many
goroutines, `db.SetMaxOpenConns(1)` for the write handle is a legitimate
and common choice — it serializes in Go rather than in the database.

## 1. The schema applies, once

```
go run ./cmd/smoketest/sqlite-store
```

or by hand, against your own file:

```
sqlite3 cryden.db ".tables"
```

Ten tables: `users`, `sessions`, `audit_events`, `verification_tokens`,
`oauth_identities`, `totp_secrets`, `webauthn_credentials`,
`recovery_codes`, `login_attempts`, and `cryden_schema_migrations`.

That is **one migration file**, not the six `store/postgres` has. There
was no deployed SQLite database to migrate incrementally from, so the
history would have been fictional. `Migrate` is idempotent and records
what it applied, so future changes still add a numbered file:

```
sqlite3 cryden.db "SELECT * FROM cryden_schema_migrations;"
```

Call `Migrate` three times; the row count stays 1.

The four **partial** indexes are worth confirming, because they are the
entire reason `login_attempts` is its own table rather than more
`audit_events` queries:

```
sqlite3 cryden.db "SELECT name FROM sqlite_master WHERE type='index' AND sql LIKE '%WHERE%';"
```

## 2. The pragmas, and what happens without them

Open the same file with a bare DSN and ask:

```go
db, _ := sql.Open("sqlite", "file:cryden.db")
err := sqlite.CheckPragmas(ctx, db)
// errors.Is(err, sqlite.ErrForeignKeysDisabled) → true
// errors.Is(err, sqlite.ErrNoBusyTimeout)       → true
```

It reports **both** problems in one error rather than stopping at the
first, so a single startup log tells you everything you need to fix.
`journal_mode` is deliberately **not** checked: rollback-journal mode is
slower under concurrency but not wrong, and a host on a filesystem where
WAL is unavailable — some network mounts — has no way to comply.

## 3. Deleting a user, with foreign keys off

This is the one to run deliberately in the broken configuration, because
that is the configuration the code exists to survive.

```go
db, _ := sql.Open("sqlite", "file:test.db") // no pragmas at all
sqlite.Migrate(ctx, db)

// Confirm the database really is not enforcing anything:
//   sqlite3 test.db "PRAGMA foreign_keys;"  → 0

users := sqlite.NewUserStore(db)
// ... create a user, a session, an audit event, a login attempt,
//     a TOTP secret, recovery codes, an OAuth identity, a token ...
users.Delete(ctx, userID)
```

Then check each table:

```
sqlite3 test.db "SELECT COUNT(*) FROM sessions WHERE user_id = 'the-id';"             -- 0
sqlite3 test.db "SELECT COUNT(*) FROM verification_tokens WHERE user_id = 'the-id';"  -- 0
sqlite3 test.db "SELECT COUNT(*) FROM oauth_identities WHERE user_id = 'the-id';"     -- 0
sqlite3 test.db "SELECT COUNT(*) FROM totp_secrets WHERE user_id = 'the-id';"         -- 0
sqlite3 test.db "SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = 'the-id';" -- 0
sqlite3 test.db "SELECT COUNT(*) FROM recovery_codes WHERE user_id = 'the-id';"       -- 0
sqlite3 test.db "SELECT COUNT(*), COUNT(user_id) FROM audit_events;"                  -- 1, 0
sqlite3 test.db "SELECT COUNT(*), COUNT(user_id) FROM login_attempts;"                -- 1, 0
```

The last two are the asymmetry: `audit_events` and `login_attempts`
declare `ON DELETE SET NULL`, not `CASCADE`, and the hand-written
cascade matches that — **the security record of what happened outlives
the account it happened to.** A `COUNT(*)` of 1 with a `COUNT(user_id)`
of 0 is exactly a surviving row whose `user_id` was NULLed.

Another account's rows must be untouched. If they aren't, the `WHERE`
clauses are wrong, which no amount of pragma correctness would have
caught.

## 4. Timestamps

The format is the schema's load-bearing detail, so look at it raw:

```
sqlite3 cryden.db "SELECT created_at, LENGTH(created_at) FROM users LIMIT 1;"
```

Expect a 30-character string like `2026-09-05T12:34:56.100000000Z`. Note
the trailing zeros. `time.RFC3339Nano` **trims** those, which is why
nothing here formats with it — a trimmed value is a different width, and
a different width sorts wrongly against a padded one.

Then confirm ordering is real, not incidental:

```
sqlite3 cryden.db "SELECT created_at FROM sessions ORDER BY created_at DESC LIMIT 5;"
```

Newest first, and identical to what `ListByUser` returns in Go. Both are
string comparisons on the same column.

Declared types, which is a driver-safety property rather than a
formatting one:

```
sqlite3 cryden.db "SELECT name, type FROM pragma_table_info('users');"
```

`created_at`, `updated_at` and `locked_until` are all `TEXT`. If any of
them ever reads `DATETIME`, `mattn/go-sqlite3` will start handing back
`time.Time` values and every scan in the package breaks.

## 5. The one Postgres-ism that needed no translation

`ON CONFLICT (user_id) DO UPDATE` is used verbatim — SQLite has had
upsert since 3.24 (2018). What it does here is security-relevant:

```go
totp := sqlite.NewTOTPStore(db)
totp.Upsert(ctx, store.TOTPSecret{UserID: id, EncryptedSecret: "first"})
totp.Confirm(ctx, id)
// Login now returns *auth.ErrSecondFactorRequired.

totp.Upsert(ctx, store.TOTPSecret{UserID: id, EncryptedSecret: "second"})
// confirmed_at is back to NULL, and Login issues tokens again.
```

Re-enrolling produces a **new** secret, and the confirmation that proved
possession of the old one says nothing about this one. Carrying it over
would let an unverified secret gate logins. Also confirm the row count
stays at 1 — an upsert that inserted instead of updating would leave two
secrets for one account:

```
sqlite3 cryden.db "SELECT COUNT(*) FROM totp_secrets WHERE user_id = 'the-id';"
```

## 6. The ones that did need translation

Nothing to run here — this is the list to check against if you are
comparing the two backends' SQL side by side. Each has a different real
solution, not a syntax swap:

| Postgres | here | why |
| --- | --- | --- |
| `UPDATE … RETURNING` | `UPDATE` then `SELECT`, one transaction | `RETURNING` needs SQLite 3.35 (Mar 2021); Debian bullseye ships 3.34.1. The shared transaction is what keeps the returned number the one this call produced. |
| `COUNT(*) FILTER (WHERE …)` | `COUNT(CASE WHEN … THEN 1 END)` | `FILTER` needs 3.30. `COUNT` and not `SUM`: over zero rows `COUNT` is 0, whereas `SUM` is NULL and would not scan into an `int`. |
| `gen_random_uuid()` | `uuid.NewV7()` in Go | no UUID function in SQLite core. V7 is time-ordered, which suits the created-at indexes. |
| `now()` / `DEFAULT now()` | a Go `time.Now()` the store passes in | keeps one formatting path, so every timestamp is the same fixed width. |
| `JSONB` | `TEXT` holding JSON | SQLite's `json_*` functions read text. `json_valid()` and `json_extract()` still work, which the tests use. |
| `BYTEA` | `BLOB` | `credential_id` stays byte-exact, including embedded `0x00`. |
| `ILIKE` | `LIKE` | SQLite's `LIKE` already folds ASCII case. See the known limits below. |
| `$1, $2` | `?` | the only genuinely cosmetic one. |
| a read-only Postgres role | a `mode=ro` DSN | see the next section. |

**Timestamps that Postgres assigns, this backend also assigns.** Where
Postgres uses `DEFAULT now()` — every `created_at`, plus
`users.updated_at` — the store assigns the value and ignores whatever
was in the struct field. Where Postgres passes a caller value as a query
parameter — `VerificationToken.ExpiresAt`, `LockAccount(until)` — the
caller's value is honoured. Honouring a caller-supplied `CreatedAt` here
would have been strictly more convenient for tests and strictly a
cross-backend divergence, so it doesn't.

## 7. The AI query surface, and its actual boundary

In `store/postgres` the guarantee is a read-only **role**. Here it is a
second handle on the same file, opened read-only:

```go
ro, _ := sql.Open("sqlite", "file:cryden.db?mode=ro")
queries := sqlite.NewSafeQueryStore(ro)
```

Hand that handle to this store and **nothing else**. That is the real
boundary: even a bug in `ai.validateIntent`, or in the query building,
cannot cause a write if the handle is physically incapable of one.
Allowlist validation is defense-in-depth on top, not a substitute.

Verify the boundary by trying to cross it:

```go
_, err := ro.ExecContext(ctx, "DELETE FROM users") // errors: readonly database
_, err = ro.ExecContext(ctx, "DROP TABLE sessions") // errors
```

`mode=ro` and **not** `PRAGMA query_only`: the pragma is per-connection,
and a pool opens new connections whenever it likes, so a pragma set on
one says nothing about the next. A read-only handle applies to every
connection the pool ever makes.

Then the allowlist, each of which must be refused:

```go
queries.RunSafeQuery(ctx, ai.QueryIntent{Entity: "totp_secrets"})            // not allowlisted
queries.RunSafeQuery(ctx, ai.QueryIntent{Entity: "users; DROP TABLE users"}) // not allowlisted
queries.RunSafeQuery(ctx, ai.QueryIntent{Entity: "users",
    Filters: []ai.QueryFilter{{Field: "password_hash", Operator: "=", Value: "x"}}})
queries.RunSafeQuery(ctx, ai.QueryIntent{Entity: "sessions",
    Filters: []ai.QueryFilter{{Field: "token_hash", Operator: "=", Value: "x"}}})
queries.RunSafeQuery(ctx, ai.QueryIntent{Entity: "users",
    Filters: []ai.QueryFilter{{Field: "email", Operator: "!=", Value: "x"}}})
queries.RunSafeQuery(ctx, ai.QueryIntent{Entity: "users",
    Aggregate: "group_by", GroupBy: "password_hash"})
```

And confirm a value shaped like an injection is inert rather than
rejected — it is bound as a parameter, so it simply matches nothing and
the table is still there afterwards:

```go
queries.RunSafeQuery(ctx, ai.QueryIntent{Entity: "users",
    Filters: []ai.QueryFilter{{Field: "email", Operator: "=", Value: "' OR 1=1; DROP TABLE users; --"}}})
```

`RunSafeQuery` re-checks membership itself rather than trusting
`ai.ExecuteQuery` to have done it, which is why every one of the above
fails even when called directly.

## 8. In-memory databases, and the trap

`:memory:` is the obvious choice for a test suite and it does not work
the obvious way. A bare in-memory database belongs to **one connection**,
and `*sql.DB` is a pool:

```go
db, _ := sql.Open("sqlite", ":memory:")
sqlite.Migrate(ctx, db)          // succeeds, on whichever connection it got
held, _ := db.Conn(ctx)          // hold that one
db.QueryRow("SELECT 1 FROM users") // opens a second → "no such table: users"
```

Under load this shows up as intermittent `no such table` errors that
vanish when you add a `SetMaxOpenConns(1)` and reappear when you remove
it. The fix is a named shared-cache DSN:

```go
sql.Open("sqlite", "file:whatever?mode=memory&cache=shared&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
```

The smoke test demonstrates both halves. This package's own tests use
files under `t.TempDir()` instead, which also exercises WAL and
`busy_timeout` — settings that do not exist for a memory database.

## 9. Everything single-use is single-use

No `RETURNING` below 3.35 means each of these is an explicit
`AND … IS NULL` plus a checked row count. If any consumed twice, a stolen
token or a leaked recovery code would be reusable:

```go
verifications.MarkUsed(ctx, id)             // ok
verifications.MarkUsed(ctx, id)             // store.ErrNotFound
codes.Consume(ctx, userID, hash)            // ok
codes.Consume(ctx, userID, hash)            // store.ErrNotFound
sessions.Revoke(ctx, sessionID)             // ok
sessions.Revoke(ctx, sessionID)             // store.ErrNotFound
```

Two lookups deliberately do **not** hide rows, and both matter:

- `GetByTokenHash` returns **expired** verification tokens. The caller
  decides what expiry means; a lookup that hid them would report "no such
  token" for a token that exists.
- Session lookups return **revoked** sessions. Reuse detection needs that
  row — hiding it would turn a replay attack into a plain "not found".

Regenerating recovery codes must invalidate the whole previous batch.
There is no incremental add, so a leaked sheet is dead the moment a new
one is printed.

## Postgres

Unaffected. Nothing in `store/postgres/` was touched, no interface
changed, and no shared code was refactored to accommodate this. If you
run Postgres, this item adds a directory you never compile and a
test-only module dependency you never load.

## Known limits

- **One writer at a time.** SQLite's concurrency model, not a property of
  this code. `busy_timeout` turns contention into a wait instead of an
  error and WAL keeps readers going, but a write-heavy multi-instance
  deployment wants Postgres. This backend is for single-process hosts,
  embedded and desktop use, CI, and local development.
- **`LIKE` is not `ILIKE` outside ASCII.** SQLite's `LIKE` folds case for
  ASCII only; Postgres's `ILIKE` folds Unicode. The fields the AI query
  surface can reach are emails, IPs and event types, so ASCII is the
  whole range in practice — but a `contains` filter on a non-ASCII value
  will match case-sensitively here and case-insensitively there, unless
  you load the ICU extension.
- **The pragma DSN is your responsibility and its syntax is your
  driver's.** `CheckPragmas` tells you when it's wrong; it cannot fix it,
  because a pragma set on one pooled connection says nothing about the
  next. Run it at startup.
- **No driver is bundled, deliberately.** `store/sqlite` imports none, so
  a host picks its own and Postgres users load nothing. The consequence
  is that forgetting the `_ "modernc.org/sqlite"` blank import produces
  `unknown driver "sqlite"` at `sql.Open`, not a compile error.
- **The schema is one file with no history.** There was no deployed
  SQLite database to migrate incrementally from, so the six-file Postgres
  history was consolidated rather than transcribed. Future changes add
  numbered files normally.
- **`ai.SafeQueryStore` is only as safe as the handle you give it.**
  Passing your read-write `*sql.DB` compiles, runs, and silently discards
  the guarantee the whole design rests on. There is no way for the store
  to detect it — a read-only *handle* is the check.
- **Timestamp text differs from Postgres's rendering.** Both are RFC
  3339 and both parse; the SQLite one is zero-padded to a fixed width. If
  you diff two backends' raw output, expect that difference and not a bug.
