# Manual test guide — named/fingerprinted sessions

A session list that shows `01a06e3f-9331-707a-b540-9854bf6d5f76` asks
someone to recognize a UUID. `ListNamedSessions` shows
**"Chrome on Windows — San Francisco, CA"** instead, so the row they
don't recognize is the row they revoke.

Two things make up a label:

- the **device** half, parsed from the `User-Agent` the session already
  carries. Pure string matching, no network call, always available.
- the **location** half, resolved from the session's IP by a
  `security.IPGeolocator` the **host app supplies**. The engine ships
  zero implementations of it, for the same reason it ships none of
  `BreachedPasswordChecker`: placing an address means an outbound call
  or a licensed database, and the engine does neither on its own
  initiative.

Both halves are computed **on read**. Nothing is stored, there is **no
migration for this feature**, and every session ever recorded gets a
label the first time you call it — including sessions created before
this code existed.

The fastest full check is the smoke test:

```
go run ./cmd/smoketest/named-sessions
```

42 checks over seven scenarios, no database required. What follows is the
same ground by hand.

## Setup

Nothing is required. With no geolocator configured, labels are
device-only and everything else behaves identically:

```go
engine, _ := cryden.New(cryden.Config{
    JWTSecret: os.Getenv("CRYDEN_JWT_SECRET"),
    Users:     users,
    Sessions:  sessions,
    Audit:     audit,
})
```

To get the location half, implement the one-method interface against
whatever you already have — a geo-IP database on disk, a provider API,
or the country header your CDN already puts on the request:

```go
type cdnHeaderGeolocator struct{ byIP *lru.Cache }

func (g cdnHeaderGeolocator) Locate(ctx context.Context, ip string) (security.Location, error) {
    v, ok := g.byIP.Get(ip)
    if !ok {
        // Unplaceable is not an error: private ranges, carrier NAT and
        // addresses you have no data for are all normal.
        return security.Location{}, nil
    }
    return v.(security.Location), nil
}

engine, _ := cryden.New(cryden.Config{
    // ...
    Geolocator: cdnHeaderGeolocator{byIP: cache},
})
```

Two things to know about the contract:

- **Return the zero `Location` with a nil error** for an address you
  simply can't place. Return an error only when the lookup itself
  failed.
- **Granularity is yours.** `Location.String()` joins the non-empty
  fields with `", "` and does nothing else — fill in `City`+`Region`
  and labels read "San Francisco, CA"; add `Country` and they read
  "San Francisco, CA, US". The engine never abbreviates, expands or
  invents a field.

## Reading the results

```go
list, err := cryden.ListNamedSessions(ctx, engine, userID)
```

Each element embeds `store.PublicSession` (so `ID`, `IP`, `UserAgent`,
`CreatedAt` are all right there, and `TokenHash`/`FamilyID` are not)
plus:

| Field | Example | Use |
|---|---|---|
| `Label` | `"Chrome on Windows — San Francisco, CA"` | print it |
| `Device.Browser` | `"Chrome"` | group/sort |
| `Device.OS` | `"Windows"` | group/sort |
| `Device.Form` | `"desktop"`, `"mobile"`, `"tablet"`, `"bot"` | icons, grouping |
| `Location.City` / `.Region` / `.Country` | `"San Francisco"` / `"CA"` / `""` | your own formatting |

`Label` is never empty. The fallbacks, in order:

| Known | Label |
|---|---|
| device + location | `Chrome on Windows — San Francisco, CA` |
| device only | `Chrome on Windows` |
| OS only (in-app webviews) | `iOS — Berlin, DE` |
| neither | `Unknown device` |

`session.Label(device, location)` is exported if you resolve location at
your own layer and want strings identical to the engine's.

## 1. A browser login gets both halves

Log in from a real browser with a geolocator configured that knows the
address, then list:

```
Chrome on Windows — San Francisco, CA
```

Check `Device.Form == "desktop"`, `Location.City == "San Francisco"`,
and that `IP`/`UserAgent` are still the raw recorded values — the label
is an addition, not a replacement.

## 2. Several devices, one account

Log in from a laptop and a phone **on the same connection**, then from
somewhere else:

```
Chrome on Windows — San Francisco, CA
Safari on iOS — San Francisco, CA
Firefox on Linux — Berlin, DE
```

The thing to verify here is the **lookup count**: two distinct addresses
across three sessions is **two** `Locate` calls, not three. Log inside
your geolocator and count them. The cache is per call, so a second
`ListNamedSessions` legitimately asks again — a session's location can
change hands, and caching across calls would need an invalidation story
this feature doesn't need to have.

## 3. No geolocator configured

Build the engine without `Geolocator` and list the same sessions:

```
Chrome on Windows
Safari on iOS
```

Every `Location` must be the zero value. Nothing invented, nothing
guessed, no trailing dash.

## 4. The geolocator is down

Make `Locate` return an error for every address. Then:

- the listing still **succeeds**;
- every session is still returned;
- labels degrade to their device half;
- a warning is logged (`session list: geolocation failed`, with the IP);
- the failure is cached like any other answer, so one listing asks
  **once**, not once per session.

This is the important negative case. That list is how someone revokes
an attacker's session — a third-party provider's uptime must never be
able to take it away from them, exactly as a breach-check failure never
blocks `SignUp`.

## 5. Clients that aren't a browser

Log in sending no `User-Agent` at all, and again from `curl`:

```
Unknown device — San Francisco, CA
curl — San Francisco, CA
```

`curl` must come back with `Device.Form == "bot"` and an **empty**
`Device.OS` — "curl on Linux" would be a device claim the string can't
support. Same for `Googlebot`, `HeadlessChrome`, `Go-http-client` and
friends.

Worth trying a handful of authentic strings by hand, because the traps
are all in the header itself:

| Sent by | Label | Why it's a trap |
|---|---|---|
| Edge | `Edge on Windows` | its UA contains both `Chrome/` and `Safari/` |
| Chrome | `Chrome on Windows` | its UA contains `Safari/` |
| iPhone Safari | `Safari on iOS` | its UA contains `Mac OS X` |
| Android Chrome | `Chrome on Android` | its UA contains `Linux` |
| ChromeOS | `Chrome on ChromeOS` | its UA contains `X11` |
| Android tablet | form `tablet` | the *absence* of `Mobile` is the only marker |
| a CUBOT handset | `Chrome on Android` | the model name contains "bot" |

## 6. Revoking from the list

List, take the `ID` off the row you don't recognize, and pass it to
`cryden.RevokeSession`. Re-list: that row is gone, the others remain.
`ListNamedSessions` is a labelled `ListSessions`, so revoked sessions
and other users' sessions are excluded by exactly the same rules.

## 7. Labels are computed, not stored

The one to check if you're upgrading an existing deployment. Log in with
**no** geolocator configured, then build a second engine over the **same
stores** with one configured, and list again:

```
before:  Chrome on Windows
after:   Chrome on Windows — San Francisco, CA
```

Same stored session, no re-login, no backfill, no migration. This is
also what makes the device parser safe to improve later: labels get
better on the next read, retroactively, for sessions that were recorded
years earlier.

## Postgres

There is nothing new to run. This feature adds **no table, no column and
no query** — it reads `IP` and `UserAgent` off the sessions
`ListByUser` already returns. If `cryden.ListSessions` works against
your Postgres deployment, so does this.

## Known limits

- **A `User-Agent` is unauthenticated, client-supplied text.** Anything
  can send anything. Treat a label as a recognition aid for a human
  reading a list, never as identity, never as a device fingerprint in
  the security sense, and never as an input to an access decision.
- **The parser is a fixed table and will age.** A browser released after
  this code degrades to its OS, or to `Unknown device`. That is a
  cosmetic regression, never a functional one, and the raw `UserAgent`
  stays exposed so a host app can run its own library over it instead.
- **No version numbers in labels.** "Chrome 124 on Windows 11" churns on
  every browser release and helps nobody pick their own laptop out of a
  list of two.
- **"Named" means engine-derived, not user-editable.** There is no
  nickname field: a host app that wants "Ray's work laptop" stores that
  itself, keyed by session ID. The engine deliberately keeps no
  user-supplied display string.
- **Location accuracy is entirely the host's.** VPNs, carrier NAT,
  corporate egress and CDN edges all mean the coarse place shown may be
  nowhere near the person. This is also why the label is informational
  and nothing in the engine acts on it.
- **The engine still ships no geolocator.** If you find one bundled,
  that's a regression against the rule this feature was built under.
