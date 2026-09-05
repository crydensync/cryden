# Manual test guide — cloud logger integrations

**There is no `logger.DatadogLogger`, and there never will be.** That is
the finding of this item, not a gap in it. Every hosted log vendor
integration is an outbound HTTPS call carrying an API key, with its own
batching, retry, backpressure and payload-shape rules — exactly the
class of thing this engine never does on its own initiative, for the
same reason it ships no `BreachedPasswordChecker` and no
`IPGeolocator`. And the universal integration point already exists:
`ConsoleJSONLogger` writes one JSON object per line to stdout, which
every log shipper in existence can already tail.

What *does* ship is everything on this side of that call — the four
things a host discovers it needs about ten minutes after pointing its
shipper at cryden's output:

| Piece | Problem it solves |
| --- | --- |
| `logger.ContextLogger` + `logger.LogFunc` + `logger.ForContext` | a record in a vendor's index is only useful if it can be tied back to the request that caused it, and the trace ID lives under a context key only the host app knows |
| `logger.NewLevelFilter` | ingestion is billed per line |
| `logger.NewMaskingRedactor` / `logger.NewHashingRedactor` | records that used to stay on your machines now sit in a third party's index |
| `logger.NewMultiLogger` | "ship it out" is almost always "ship it out **as well as** stdout" |

All four are pure local code. Nothing in `logger/` opens a socket.

The fastest full check is the smoke test:

```
go run ./cmd/smoketest/cloud-loggers
```

50 checks over eight scenarios, no database required. What follows is the
same ground by hand.

## Setup

Nothing is required. `Config.Logger` is the only knob, it is optional,
and left nil you get `ConsoleJSONLogger` exactly as before. There is
deliberately **no `Config.LogLevel`, no `Config.LogFormat` and no
`Config.RedactFields`**: a host composes wrappers around its own sink
instead, the same way `Config.RateLimiter` and `Config.Hasher` are
injected already constructed.

```go
engine, err := cryden.New(cryden.Config{
    JWTSecret: os.Getenv("JWT_SECRET"),
    Users:     users,
    Sessions:  sessions,
    Audit:     audit,
    Logger:    yourSink, // optional
})
```

## What the engine actually logs

Worth knowing before you tune anything, because it decides what a filter
saves you and what a redactor has to cover.

| Level | Roughly | Examples |
| --- | --- | --- |
| `error` | only ever "the audit store rejected a write" | `login: audit record failed` |
| `warn` | something a human might want to look at | `login: failed attempt`, `login: rate limited`, `login: account locked after repeated failures`, `anomaly: login flagged`, `credential stuffing: IP flagged` |
| `info` | completions | `signup: completed`, `login: completed`, `totp enabled`, `passkey registered` |
| `debug` | one call site in the entire engine | `credential stuffing: repeat within cooldown, not recorded` |

Messages are **constant strings**; everything variable is in `fields`.
That is what makes redaction tractable — a redactor never has to guess
at free text. The field keys, in rough order of how often they appear:

| Key | Personal data? | In `DefaultRedactedKeys()` |
| --- | --- | --- |
| `user_id`, `requesting_user_id` | yes — a stable per-person identifier | yes |
| `ip` | yes — personal data in its own right under GDPR Art. 4 | yes |
| `error`, `reason`, `provider`, `signals`, `attempts`, `n` | no | no |
| `session_id` | per-login, not per-person | no — add it yourself if your threat model wants it |
| `to`, `from` | no — these are hash *algorithm* names on the hash-upgrade record | no |

No email address is ever logged, anywhere. The closest the engine comes
is `magic link requested for unknown email`, which carries only the IP.

## 1. Nothing configured

```go
engine, _ := cryden.New(cryden.Config{ /* no Logger */ })
cryden.SignUp(ctx, engine, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4")
```

One line per record on stdout:

```json
{"level":"info","message":"signup: completed","fields":{"user_id":"0192…"},"timestamp":"2026-09-05T11:04:07.918273641Z"}
```

Check the timestamp has **sub-second precision** (`RFC3339Nano`). One
login emits several records; at second precision they arrive with
identical timestamps and nothing downstream can order them. If you see
`2026-09-05T11:04:07Z` with no fractional part on every line, that is a
regression.

## 2. Wiring your own sink

Any type with the four `logger.Logger` methods works, unchanged from
before. For a sink you don't want to declare a type for, `logger.LogFunc`
is a one-function adapter that also gets the context:

```go
sink := logger.LogFunc(func(ctx context.Context, level logger.Level, msg string, fields map[string]string) {
    yourVendorClient.Enqueue(vendor.Record{
        Level:   level.String(),          // "debug" | "info" | "warn" | "error"
        Message: msg,
        Fields:  fields,
        TraceID: yourmiddleware.TraceIDFrom(ctx), // your key, your context
    })
})
```

Two things to hold onto: `fields` is **not copied** for you, so treat it
as read-only (write to a copy if your client needs to add to it), and
the call is **synchronous** — the engine waits for it. Enqueue and
return; do not POST inline.

## 3. Trace correlation

```go
ctx := yourmiddleware.WithTraceID(r.Context(), "trace-7f3c19")
cryden.Login(ctx, engine, email, password, ip, r.UserAgent())
```

Every record from that one call arrives at a `ContextLogger` with that
context, so `traceIDFrom(ctx)` returns `trace-7f3c19`. Verify:

- a second `Login` on a **different** context gets the new trace, not the
  first one — the binding lives and dies inside one facade call.
- a plain `Logger` (four methods, no `Log`) still receives **every**
  record. `ContextLogger` is a second, optional interface precisely so
  that every host Logger written before it keeps compiling — the same
  reason `notify.MagicLinkSender` is separate from `notify.EmailSender`
  and `security.Rehasher` from `security.Hasher`.
- your sink's four bare methods are **not** called when it implements
  `Log` — if they are, a wrapper somewhere dropped the context.

`logger.ForContext(ctx, sink)` is the same mechanism if you want it
directly; the engine calls it once per facade call.

## 4. Level filtering

```go
Logger: logger.NewLevelFilter(sink, logger.LevelWarn)
```

Run a signup, a good login and a bad one. The bad login's `warn` arrives;
the two `info` completions do not. Then check the part that is easy to
get wrong: **the survivors still carry the trace ID**. A filter
forwarding through `Debug`/`Info`/`Warn`/`Error` would strip the context
on the way through, making "cheap" and "correlated" a choice nobody
should have to make. Every wrapper here implements `ContextLogger` and
forwards the context.

From an env var:

```go
min, err := logger.ParseLevel(os.Getenv("CRYDEN_LOG_LEVEL")) // "debug"|"info"|"warn"|"warning"|"error"|"err"
if err != nil { /* logger.ErrUnknownLevel — a typo, not a level */ }
```

`ParseLevel`'s first return is **meaningless when err is non-nil** — it
is the zero value, not a fallback. Decide your own default explicitly.

## 5. Redaction — masking

```go
Logger: logger.NewMaskingRedactor(sink) // no keys given → DefaultRedactedKeys()
```

Fail a login from `1.2.3.4` and read what the sink got:

- no record mentions `1.2.3.4` anywhere;
- the `ip` field is **still present**, reading `[redacted]`
  (`logger.RedactedMarker`) — the key stays so the record's shape, and
  anything your vendor indexed on it, does not change;
- `user_id` likewise;
- `reason` (`wrong_password`) comes through **untouched**, which is what
  an operator is reading the record for.

Your own keys replace the defaults rather than adding to them, so pass
both if you want both:

```go
logger.NewMaskingRedactor(sink, append(logger.DefaultRedactedKeys(), "tenant", "session_id")...)
```

Keys match **case-insensitively**: `IP`, `Ip` and `ip` are all redacted.
Empty values are left alone — there is nothing there to hide, and a
marker standing in for one would suggest otherwise.

## 6. Redaction — hashing

Masking erases the thing you most often need: "one IP, forty accounts" is
the shape credential stuffing has, and `[redacted]` forty times says
nothing.

```go
redactor, err := logger.NewHashingRedactor(sink, os.Getenv("CRYDEN_LOG_HASH_KEY"))
```

Fail three logins — twice from `1.2.3.4`, once from `203.0.113.7`:

- neither address appears in any record;
- the two attempts from the same address carry the **same**
  `hmac-sha256:<16 hex>` digest;
- the third carries a different one.

Three properties to verify deliberately, because each one is a way to
get this wrong:

- **an empty key is refused** — `logger.ErrMissingHashKey`, no redactor
  returned. Unkeyed, the entire IPv4 space is 2^32 values, so a digest of
  an address is a lookup table away from being the address.
- **the key must be identical on every replica**, or one address hashes
  two ways and the correlation is gone. Ship it like any other secret.
- **give it a value of its own**, not `Config.JWTSecret` or
  `Config.EncryptionKey`. Key separation costs nothing, and this one is
  handed to the component whose job is handing output to a third party.

Changing the key intentionally re-anonymizes history: old digests stop
matching new ones. That is a rotation strategy, not a bug.

## 7. Fan-out

```go
Logger: logger.NewMultiLogger(
    logger.NewConsoleJSONLogger(),                 // stays local, full detail
    logger.NewMaskingRedactor(vendorSink),         // leaves the building, reduced
)
```

The composition order is the whole point, and it is the one thing to get
right: **redact and filter inside the fan-out, per sink**, not around it.
Wrap the `MultiLogger` and you have redacted your own stdout too, for
nothing. Verify by reading both sinks: the local one has `1.2.3.4`, the
outbound one has `[redacted]`, both have the trace ID, both have the same
number of records. This works because a redactor **copies** the field map
when it changes something and never writes to the caller's.

`NewMultiLogger` skips nil sinks, returns the sink itself when given
exactly one, and returns a `NopLogger` when given none — so a slice
assembled from optional config needs no branching. Note that only
**untyped** nils are skipped: a typed nil pointer in an interface is not
a nil interface, the same trap `Config.Geolocator` has.

## 8. A sink that misbehaves

Put a sink that panics ahead of a good one in a `MultiLogger`, then log
in. Expect:

- the login **succeeds** — a log statement is never the point of the call
  it sits inside;
- the sink after the broken one still gets its record;
- one line per lost record on **stderr**:
  `logger: a sink panicked on a warn record ("login: failed attempt") and that record is lost: …`

Not swallowed, and not silently retried: a sink failing invisibly is
worse than one failing loudly. The recovery is scoped to the fan-out
only — a single sink wired directly as `Config.Logger` is not wrapped in
anything and will panic into your handler, which is the correct place for
it to surface.

There is no `Flush` and no `Close` anywhere in this package. Your sink is
constructed by you and held by you; shutting it down at the end of
`main` is not something the engine can sequence for you.

## Postgres

Nothing to run. This item adds **no table, no column, no query and no
dependency** — it is one new method on `*Engine` (`logFor`), a
`e.log` → `e.logFor(ctx)` substitution at 24 call sites in `cryden.go`,
and seven new files under `logger/`. `auth/`, `session/`, `token/` and
every store are untouched.

## Known limits

- **No vendor client ships, on purpose.** If you find a `DatadogLogger`
  or a `BetterStackLogger` in here, that is a regression against the rule
  this item was built under.
- **`fields` stays `map[string]string`.** Typed values would read better
  in a vendor's UI, and would break every host `Logger` implementation
  that exists. The interface is frozen; additions come as separate
  optional interfaces or wrappers.
- **Logging is synchronous and unbuffered.** A slow sink slows down the
  facade call that logged. Batching belongs in your sink.
- **A redactor covers `fields`, not messages.** Engine messages are
  constant strings, so there is nothing there to find; if your host app
  logs its own records through the same Logger and interpolates personal
  data into a *message*, this will not save you.
- **Truncated digests can theoretically collide.** 64 bits, so at any
  volume a real deployment will see this is not a practical concern, but
  it is a hash, not an injective mapping.
- **`ConsoleJSONLogger` is not a `ContextLogger`** and cannot be one: the
  key holding a trace ID belongs to the host app. If you want trace IDs
  on stdout, wrap it — a `LogFunc` that reads your key and adds it to
  `fields` before delegating is about five lines.
