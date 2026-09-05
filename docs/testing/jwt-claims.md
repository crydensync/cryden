# Manual test guide — Extensible JWT claims

An access token already carries a signed statement about who the user is.
The gap this closes is that it carried *only* that: an API gateway holding
a verified token and needing to know whether that user is an admin had to
go and ask the database, having just been handed a signed document about
the exact user in question. `Config.AccessTokenClaims` lets the host app
put the answer in the token.

```go
engine, err := cryden.New(cryden.Config{
	JWTSecret: os.Getenv("JWT_SECRET"),
	Users:     users,
	Sessions:  sessions,
	Audit:     audit,

	AccessTokenClaims: token.ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
		role, err := myapp.RoleOf(ctx, userID)
		if err != nil {
			return nil, err
		}
		return map[string]any{"role": role, "tenant": myapp.TenantOf(userID)}, nil
	}),
})
```

Read them back on the other side:

```go
userID, claims, err := cryden.VerifyTokenWithClaims(engine, accessToken)
// claims["role"] == "admin"
```

That is the whole feature. Everything below is the part worth knowing
before you wire it into something that matters.

## The shape, and why it is this shape

`NEXT.md` offered two: an `extraClaims` parameter on `Issue`, or a hook
injected once. The hook won on one fact — **the host cannot supply claims
on the refresh path.** `RefreshToken(ctx, engine, rawRefreshToken)` takes
a refresh token and nothing else; the caller is a client that does not
know who it is, let alone what role it has. A parameter would have to be
threaded through six facade functions and would still leave refreshed
tokens claimless, which is the failure mode where tokens silently work
for fifteen minutes and then quietly stop carrying authorization.

| Piece | Where | What it is |
| --- | --- | --- |
| `token.ClaimsProvider` | `token/claims.go` | The interface: `AccessTokenClaims(ctx, userID) (map[string]any, error)` |
| `token.ClaimsFunc` | `token/claims.go` | Function adapter, for providers with no state of their own |
| `token.ReservedClaimNames()` / `IsReservedClaim` | `token/claims.go` | The names a provider may not set, for the host's own tests |
| `Config.AccessTokenClaims` | `config.go` | Where it gets wired. Nil is the default and changes nothing |
| `cryden.VerifyTokenWithClaims` | `cryden.go` | `VerifyToken` plus the host's claims |
| `token.NewJWTIssuerWithClaims` | `token/jwt.go` | Constructor beside the plain one, for direct users of the package |

`Issue`/`Verify`/`NewJWTIssuer` all still exist with the same signatures.
Nothing a host wrote against v2 needs touching.

## Rules the provider lives under

1. **It cannot set the registered claims.** All seven of RFC 7519 §4.1 —
   `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti` — are refused, and
   refusing one refuses the whole set: no token is issued, and the login
   or refresh that asked for one fails with `token.ErrReservedClaim`.
   `sub` is the reason. `Verify` reads the user ID out of it, so a
   provider able to write it is a provider able to mint a token
   authenticating as somebody else.
2. **An error fails the token.** Not "issues a token without the extra
   claims." See below.
3. **Values must marshal to JSON**, and come back as JSON: an int goes in
   and a `float64` comes out.
4. **It runs on the hot path**, synchronously, on every login *and every
   refresh* — roughly every fifteen minutes per active session at the
   default `AccessTokenTTL`. A database query in there is a database
   query on that schedule.

## Why it fails closed

`security.BreachedPasswordChecker` two packages over fails *open*: if the
service is unreachable, the signup goes through. This does the opposite,
deliberately.

The difference is what the two produce. A breach check is a restriction,
and failing open on a restriction lets a legitimate user in. Claims are
authorization data, and failing open on those issues a credential
carrying less authority than it should — into a gateway that may well read
"no `role` claim" as "no restriction" rather than "no permission". The
engine will not guess which, so it declines to issue the token.

Two consequences to plan for:

- **On login**, the failed attempt leaves no session behind. The access
  token is now issued *before* the session row is written, precisely so a
  login that fails at this step does not leave a session nobody holds a
  refresh token for.
- **On refresh**, the rotation has already happened when the provider is
  called and cannot be undone. A provider that fails there costs the user
  the session, not just the request — they hold a spent refresh token and
  have to log in again. If your provider talks to something flaky, cache
  its answers.

## Hands-on

Everything below runs against in-memory stores. Nothing needs a database.

```
go test ./token/ ./...
go run ./cmd/smoketest/jwt-claims
```

75 checks over eight sections. What each one is for:

### 1. The round trip

Sign up, log in, `VerifyTokenWithClaims`. Confirms the host's claims come
back, addressed to the right user, and that the engine's own `sub`/`iat`/
`exp` are *stripped* from the returned map — a host reading its own claims
should not have to know which names to skip. Also confirms `SignUp` never
calls the provider: signup issues no access token.

### 2. The default

Same flow with `AccessTokenClaims` left nil. Claims come back as `nil`
rather than an empty map, and the token's payload holds exactly
`exp,iat,sub` — the same three it held before this feature existed.

### 3. Refresh re-evaluates

A provider that returns `member` on its first call and `admin` on the
second. The token from the login says `member`; the token from the
refresh says `admin`. This is the role-propagation story: change a role in
your own data and it lands in the next access token, without forcing the
user to log in again.

The same section pins the other half of it — the *old* access token still
verifies until it expires, still carrying `member`. That is what a bearer
token is, and the reason the default TTL is fifteen minutes rather than a
day.

### 4. Reserved names

Loops over all seven, each with a legitimate `role` claim alongside. Each
fails the login with `ErrReservedClaim`, the error names the offending
claim (a host debugging its own provider gets nothing from "a reserved
claim" alone), no tokens are returned, and no session is left behind.

Then the case-sensitivity check: `SUB` in capitals passes through as an
ordinary host claim, because JSON keys are case-sensitive and nothing
reads `SUB`.

### 5. Fail-closed

A provider that works once and then breaks. The first login succeeds — so
the failures after it are the provider's, not the engine's. Then: the
refresh fails with `ErrClaimsProvider`, the refresh token turns out to be
spent, a fresh login fails with both `ErrClaimsProvider` *and* the
provider's own error retrievable via `errors.Is`, and no session is left
behind.

### 6. Unusable claims

A claim with an empty name (`ErrEmptyClaimName`) and a value that cannot
be serialised (a channel — the JSON error from the signer names the type,
which is more useful than a sentinel would be). Both fail before a token
exists.

### 7. Algorithm confusion, still refused

This item was required not to weaken the existing `alg: none` defence.
It is stronger now, and this section proves it with tokens **forged using
the engine's own secret** — the position an attacker is in after a leak,
where the signature checks out and something else has to say no:

| Forged token | What refuses it |
| --- | --- |
| `alg: none`, `role: admin` | The keyfunc's "must be HMAC" check |
| HS512, real secret | `WithValidMethods(["HS256"])` — HS512 *is* HMAC, so the keyfunc alone would pass it |
| HS256, no `exp` | `WithExpirationRequired()` — otherwise valid forever |
| HS256, no `sub` / numeric `sub` | The subject assertion in `VerifyWithClaims` |
| Expired | Standard `exp` validation |
| Honest token, one payload byte changed | The signature |
| Empty string | Parsing |

Each returns `ErrInvalidAccessToken` and — worth checking explicitly —
*no* user ID and *no* claims, so a caller ignoring the error still gets
nothing usable. The honest token is verified again at the end, so "all of
these fail" is not just "everything fails."

### 8. What is actually on the wire

Prints the decoded payload. The claims are base64, **not encryption** —
anyone holding the token reads them. Two things follow: do not put
anything in there you would not put in a URL, and watch the size. Tokens
travel in every `Authorization` header; the sample here is 229 bytes with
two claims, and there is deliberately no size cap in the engine, so a
provider returning a large object is a header your proxy may reject.

## Trying it by hand

The fastest way to see it end to end, without the smoke test:

```go
engine, _ := cryden.New(cryden.Config{
	JWTSecret: "dev-secret",
	Users:     memory.NewUserStore(),
	Sessions:  memory.NewSessionStore(),
	Audit:     memory.NewAuditStore(),
	AccessTokenClaims: token.ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
		return map[string]any{"role": "admin"}, nil
	}),
})

ctx := context.Background()
cryden.SignUp(ctx, engine, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4")
tokens, _ := cryden.Login(ctx, engine, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4", "cli")

fmt.Println(tokens.AccessToken) // paste into jwt.io — the claim is right there
```

Then break it on purpose: return `map[string]any{"sub": "someone-else"}`
and watch the login fail rather than the token lie.

## Postgres

Nothing to run. No schema changed, no store was touched — claims are
computed at issue time and live only inside the signed token. The
`sessions` table is byte-for-byte what it was.

## Known limits

- **No size cap.** The engine will happily sign a 4 KB claim set and let
  your reverse proxy be the one to complain. Documented rather than
  enforced, because a limit low enough to be safe everywhere would be too
  low to be useful anywhere.
- **No `sid` claim.** The token does not carry its session ID, so a
  gateway cannot correlate a token with a session without a lookup. Out
  of scope here; it would be a registered-adjacent claim the engine sets
  itself, not host data.
- **Claims are a snapshot.** Revoking a role does not reach a token
  already issued. The mitigation is the TTL, not this feature.
- **One provider, all tokens.** There is no per-login or per-scope
  variation — the provider gets `ctx` and a user ID, and whatever it
  returns goes into that token. Anything finer belongs in the provider's
  own logic, reading what it needs out of `ctx`.
