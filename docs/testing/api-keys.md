# Manual test guide — API keys / machine-to-machine auth

Everything the engine could authenticate until now was a person: a
password, a code from a phone, a link in an email, a passkey. A CI job
has none of those, and the workaround is always the same — a service
account with a password in an environment variable, logging in every
fifteen minutes to get an access token it will use once.

An API key is the credential that fits that caller. One opaque string,
presented on every request, resolving to a user and a set of scopes:

```go
engine, err := cryden.New(cryden.Config{
	JWTSecret: os.Getenv("JWT_SECRET"),
	Users:     users,
	Sessions:  sessions,
	Audit:     audit,

	APIKeys:      apiKeys, // store.APIKeyStore
	APIKeyPrefix: "acme",  // default "ck"
})
```

Mint one for an already-authenticated user:

```go
raw, key, err := cryden.GenerateAPIKey(ctx, engine, userID, "ci deploy",
	[]string{"deploy:write"}, 0) // 0 = never expires

// raw is "acme_9f3a1c02…" and this is the only time it exists.
// key.Prefix is "acme_9f3a1c02" — the part a UI may show forever.
```

And on the machine's side of the wire:

```go
identity, err := cryden.AuthenticateAPIKey(ctx, engine, presentedKey)
if err != nil {
	// auth.ErrInvalidAPIKey, whatever went wrong
}
identity.UserID          // who this key acts as
identity.HasScope("deploy:write")
```

That is the whole feature. Everything below is what to know before
putting it in front of something that matters.

## The shape

| Piece | Where | What it is |
| --- | --- | --- |
| `store.APIKey` | `store/interfaces.go` | The row: user, name, prefix, hash, scopes, expiry, last-used, revoked-at |
| `store.APIKeyStore` | `store/interfaces.go` | Five methods. Implemented for memory, Postgres and SQLite |
| `Config.APIKeys` | `config.go` | Where it gets wired. Nil is the default and changes nothing |
| `Config.APIKeyPrefix` | `config.go` | The greppable label. Default `"ck"`; no whitespace, no underscore |
| `cryden.GenerateAPIKey` | `cryden.go` | Mints one. Returns the raw key exactly once |
| `cryden.AuthenticateAPIKey` | `cryden.go` | The M2M login path |
| `cryden.ListAPIKeys` | `cryden.go` | The "your API keys" screen |
| `cryden.RevokeAPIKey` | `cryden.go` | Stops one, permanently |
| `cryden.APIKey` / `APIKeyIdentity` | `cryden.go` | The public views. Neither carries the secret or its hash |

`ListAPIKeys` is not in the item's spec, which asked for generate,
revoke and validate. It is here because `RevokeAPIKey` takes a key ID,
and without this there is no way for a host to obtain one after
creation — the spec's three functions do not compose into a working
feature on their own.

## Decisions, and why they went that way

**SHA-256, not bcrypt.** The same fast hash as refresh tokens and
recovery codes, for the same reason: a key is 32 bytes from
`crypto/rand`, not a human password, so there is no dictionary to slow
an attacker down through. There is also a throughput argument that
does not apply to the others — a key is verified on *every* machine
request, so a bcrypt cost would be paid per call on the hottest path
in the engine.

**Outside the second-factor system entirely.** A key does not go
through `Login`, does not produce `*ErrSecondFactorRequired`, and is
not one of the methods that error advertises. There is no human behind
a deploy pipeline to prompt for a code; a key that resolved and then
asked for one would simply hang.

**Lockout does not reach keys.** Failed *password* attempts lock the
password path only. Honouring lockout here would mean anyone who knows
a developer's email address can take down that account's production
integrations by failing to log in as them five times. Revoking the key
is what stops the key. The smoke test demonstrates this rather than
just asserting it.

**Every failure is `auth.ErrInvalidAPIKey`.** Unknown, revoked,
expired, malformed, empty — one error. A caller able to tell "never
existed" from "revoked last week" can sort the keys it stole into live
and dead. `RevokeAPIKey` is the same three-way silence
(`auth.ErrAPIKeyNotFound` covers nonexistent, already-revoked, and
somebody else's).

**A key carries the user's full authority.** `AuthenticateAPIKey`
returns a `UserID` and the engine stops there. Scopes are host-defined
strings it stores and hands back without ever interpreting —
`HasScope` is exact string equality, with no hierarchy and no
wildcards. If your key is meant to be able to deploy but not to delete
the account, that check is yours to write and yours to enforce at
every endpoint.

**Expiry is optional and secondary.** `ttl` of 0 means never, which is
the honest default for a credential living in a pipeline's
environment. Expiry helps hosts that want forced rotation; it is not
what stops a leaked key.

## What lands in the audit log

| Event | When | Metadata |
| --- | --- | --- |
| `api_key_created` | `GenerateAPIKey` succeeds | `key_id`, `prefix`, `scopes` |
| `api_key_revoked` | `RevokeAPIKey` succeeds | `key_id` |
| `api_key_rejected` | A real key is refused | `key_id`, `reason` (`revoked` or `expired`) |

Two absences are deliberate. A **successful** authentication records
nothing: it happens on every machine request, and a row per request
would bury everything else in the table. An **unrecognised** key
records nothing either — that is unauthenticated traffic from anywhere
on the internet, and auditing it would turn this into a write endpoint
into your audit table for anyone with a wordlist. Your request log is
where those belong, with the rate limiting to match.

A key that exists but is no longer usable is the case worth recording:
only somebody who once held a real credential for that account can
trigger it, and "the key you revoked on Tuesday is still being
presented every minute" is something its owner wants to know.

## Hands-on

Everything runs against in-memory stores. Nothing needs a database.

```
go test ./...
go run ./cmd/smoketest/api-keys
```

96 checks over ten sections:

1. **A key authenticates a machine.** The round trip, the key's shape,
   the prefix fragment, whitespace tolerance, and that the stored row
   contains no trace of the raw secret.
2. **Unconfigured.** All four functions return
   `ErrAPIKeysNotConfigured` with nil `Config.APIKeys`, and password
   login is untouched.
3. **Listing.** Newest first, scopes visible, `LastUsedAt` nil until
   first use, a custom prefix in effect, and another user's keys out of
   scope.
4. **Revocation.** The key stops immediately, a second revoke reports
   not-found, and one user revoking another's key neither succeeds nor
   breaks anything.
5. **Expiry.** A one-nanosecond TTL, so the key is past its expiry by
   the next line — the same code path a ninety-day key takes on day
   ninety-one. Expired keys stay *listed*.
6. **Refused keys.** Nine wrong things, including the real key with one
   character changed, truncated, and with its prefix swapped. Each
   returns `ErrInvalidAPIKey` and an empty identity, so a caller
   ignoring the error still gets nothing usable. The honest key is
   checked again at the end.
7. **Refused arguments.** Empty and whitespace-bearing scopes (the
   error names the offender), a negative TTL, an unknown user, and an
   `APIKeyPrefix` containing the separator — rejected by `New`, not by
   the first `GenerateAPIKey` months later.
8. **Lockout does not reach keys.**
9. **The audit trail.** Including five successful uses and five unknown
   keys, both recording nothing.
10. **What is actually stored.** Prints the raw key, its SHA-256, and
    the prefix side by side.

## Trying it by hand

```go
engine, _ := cryden.New(cryden.Config{
	JWTSecret: "dev-secret",
	Users:     memory.NewUserStore(),
	Sessions:  memory.NewSessionStore(),
	Audit:     memory.NewAuditStore(),
	APIKeys:   memory.NewAPIKeyStore(),
})

ctx := context.Background()
user, _ := cryden.SignUp(ctx, engine, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4")
raw, key, _ := cryden.GenerateAPIKey(ctx, engine, user.ID, "cli", []string{"read"}, 0)

fmt.Println(raw)                                        // the only time it exists
fmt.Println(cryden.AuthenticateAPIKey(ctx, engine, raw)) // → identity
cryden.RevokeAPIKey(ctx, engine, user.ID, key.ID)
fmt.Println(cryden.AuthenticateAPIKey(ctx, engine, raw)) // → ErrInvalidAPIKey
```

The middleware around it is yours. The engine never reads an
`Authorization` header; extracting the key from `Bearer <key>`, or
`X-API-Key`, or wherever your callers put it, is the host's job.

## Postgres

One new migration, `0007_api_keys.up.sql`. It must run before any of
this works:

```
psql "$DATABASE_URL" -f store/postgres/migrations/0007_api_keys.up.sql
```

The table is `api_keys`, with `key_hash` unique — that index is the one
the hot read uses — and a partial index on `(user_id) WHERE revoked_at
IS NULL` for the listing. `user_id` is `ON DELETE CASCADE`: a key
outliving its owner would authenticate as nobody.

## SQLite

`store/sqlite/migrations/0002_api_keys.up.sql`, applied by the embedded
runner:

```go
sqlite.Migrate(ctx, db)
```

Timestamps are TEXT in the fixed-width layout the rest of that package
uses, so `ORDER BY created_at DESC` is a text comparison that happens
to be chronological. `scopes` is TEXT holding JSON. The foreign key is
declared but only enforced with `PRAGMA foreign_keys = ON`, which is
why `UserStore.Delete` deletes these rows by hand as well.

## Known limits

- **No rate limiting on the M2M path.** `AuthenticateAPIKey` does not
  consult `Config.RateLimiter`. Limiting by key would need a key to
  limit *by*, which means hashing and looking it up first — at which
  point the work is already done — and limiting by IP would throttle a
  legitimate CI runner making a thousand calls a minute. Rate limiting
  machine traffic belongs at the edge, where the request count lives.
- **Key entropy follows `RefreshTokenByteLength`.** Keys reuse the
  engine's configured token generator rather than adding a knob, so a
  host that lowered that to the 16-byte minimum gets 16-byte keys.
  128 bits is still far beyond guessable; if you want more, raise the
  one setting.
- **The prefix reveals 8 characters of the secret** — 32 of its 256
  bits, so that a UI can tell one key from another. This is the GitHub
  convention and it changes nothing about guessability.
- **`LastUsedAt` is coarse.** Written at most once every five minutes
  per key. It answers "is this still in use", not "when exactly was
  the last request". A per-request access log is the host's, not the
  engine's.
- **No rotation helper.** Rotating is generate-then-revoke, in that
  order, by the host. An engine-side `RotateAPIKey` would have to guess
  the overlap window, and the host is the only party that knows when
  its deploy has picked the new key up.
- **No IP allowlist per key**, no per-key rate limit, no "this key may
  only read" enforced by the engine. All three are real things to want
  and all three are the host's, since only the host knows what its
  scopes mean.
- **The in-memory `UserStore.Delete` does not cascade** to keys, as it
  does not to sessions or anything else — the memory stores are
  independent maps with no knowledge of each other, and are test
  fixtures. Both real backends cascade.
