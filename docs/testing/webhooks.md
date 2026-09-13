# Manual test guide — Webhooks

The engine already knew when an account was locked, a password changed,
a refresh token reused. It wrote all of it to the audit table and waited
to be asked. A host app that wanted to send "was this you?" the moment
an email address changed had one option: poll its own audit table on a
timer and diff the result.

`Config.Webhooks` inverts that. The host hands the engine an
implementation, and the engine hands it every subscribed event as it is
recorded:

```go
engine, err := cryden.New(cryden.Config{
	JWTSecret: os.Getenv("JWT_SECRET"),
	Users:     users,
	Sessions:  sessions,
	Audit:     audit,

	Webhooks: myapp.EventQueue{}, // notify.WebhookSender
	// WebhookEvents left unset = cryden.DefaultWebhookEvents()
})
```

The implementation is the host's, entirely — the engine ships none,
makes no HTTP call, and has no opinion about your endpoint:

```go
type EventQueue struct{ q *myqueue.Client }

func (e EventQueue) SendWebhook(ctx context.Context, event notify.WebhookEvent) error {
	// Enqueue. Do NOT make the HTTP call here — see below.
	return e.q.Publish(ctx, "cryden.events", event)
}
```

That is the whole feature. Everything below is what to know before
pointing it at production.

## The shape

| Piece | Where | What it is |
| --- | --- | --- |
| `notify.WebhookSender` | `notify/webhook_sender.go` | The interface: `SendWebhook(ctx, WebhookEvent) error` |
| `notify.WebhookEvent` | `notify/webhook_sender.go` | The payload: `ID`, `Type`, `UserID`, `IP`, `Metadata`, `OccurredAt` |
| `Config.Webhooks` | `config.go` | Where it gets wired. Nil is the default and changes nothing |
| `Config.WebhookEvents` | `config.go` | Which events reach it. Empty means the default subset |
| `cryden.DefaultWebhookEvents()` | `webhooks.go` | The subset, as a fresh slice you can append to |
| `webhookRecorder` | `webhooks.go` | Unexported. The wiring — see below |

`notify` imports nothing but `context` and `time`, so implementing
`WebhookSender` needs no import from the engine's internals. `Type` is
a plain string carrying the `store.AuditEventType` that was recorded.

## How it is wired, and why that way

There is no event bus. The recorder **decorates the host's
`store.AuditStore`**: `New` wraps `Config.Audit`, `Record` writes the
row and then dispatches, and every one of the engine's 33 existing
`audit.Record` call sites notifies without a line changing. Nothing in
`auth/` knows this type exists — every call site there holds
`store.AuditStore`.

The alternative was a `notify.WebhookSender` parameter threaded through
those 33 sites. Beyond the diff, the reason not to is what happens
afterwards: a second mechanism alongside `audit.Record` is a second
thing to remember at every call site added later, and the cost of
forgetting is an event that is audited but never delivered — invisible
in every test, noticed only by the host who needed it. Wrapped here, an
event that reaches the audit log reaches the filter.

Two consequences worth knowing:

- **Reads are untouched.** Only `Record` is decorated; `ListByUser` and
  `SearchByType` are the wrapped store's own.
- **The audit row is written first.** It is the system of record, a host
  that reacts to a webhook by reading the audit log finds the event
  already there, and a process dying between the two loses the
  notification rather than the evidence.

## The default subset

`WebhookEvents` left empty subscribes to sixteen events — the ones
bounded by real human action:

| Group | Events |
| --- | --- |
| The account | `signup_success`, `account_deleted` |
| Credentials | `password_changed`, `email_changed` |
| Sign-in methods | `oauth_linked`, `totp_enabled`, `totp_disabled`, `webauthn_registered`, `webauthn_removed`, `recovery_codes_generated`, `api_key_created`, `api_key_revoked` |
| Something is wrong | `account_locked`, `token_reuse_detected`, `anomaly_detected`, `credential_stuffing_detected` |

Three are left out deliberately, and they are the three a host is most
likely to ask for first:

| Excluded | Volume |
| --- | --- |
| `login_success` | Every login, of every user, forever |
| `token_rotated` | Every refresh — once per active session per `AccessTokenTTL`. A thousand logged-in users at the default fifteen minutes is 4,000 deliveries an hour |
| `login_failed` | Chosen by whoever is attacking you. Subscribing turns a password-guessing script into load on your endpoint |

You can have them anyway — the list is exactly the list:

```go
WebhookEvents: append(cryden.DefaultWebhookEvents(), store.EventLoginSuccess),
```

There is deliberately **no "all" switch**. An `all` would silently start
delivering every event type added to the engine after you wrote your
sender, including the next high-volume one.

## Rules the sender lives under

1. **It runs synchronously, on the request path**, in the same goroutine
   as the login that triggered it, immediately after the audit write.
   Whatever it costs is added to that operation's latency. **Enqueue;
   do not call.** An `http.Client.Do` in `SendWebhook` is a third
   party's downtime becoming your login latency, and their timeout
   becoming your p99.
2. **An error never fails the operation.** It is logged at Error level
   and the login succeeds — the same fire-and-forget contract the audit
   write above it has. A webhook is a notification, not a gate.
3. **A panic is not an error.** It propagates and takes the request
   with it. The engine recovers nowhere except across a `MultiLogger`'s
   sinks, where recovery has a second sink to preserve the record in
   (`logger/multi.go`); one sender has no second anything, so a
   panicking one is a host bug that fails loudly on the first request
   instead of quietly dropping events for months.
4. **A failed audit write still delivers.** The event happened either
   way, and a host told about a lockout it cannot find a row for is
   better served than one told nothing because the database blinked.
5. **`ctx` is the request's own**, so a host's tracing middleware is
   readable from inside `SendWebhook` — and it may already be cancelled
   by the time a slow sender uses it. One more reason for the enqueue: a
   queue write that ignores a cancelled `ctx` still delivers, while an
   HTTP call inheriting it silently does not.
6. **`Metadata` is a copy.** Keep it, edit it, hold it past the call —
   it cannot reach the audit record.
7. **`ID` is a delivery ID, not the audit row's.** The stores assign
   their own and do not report them back. It is there so a receiver can
   be idempotent; correlate on `Type` + `UserID` + `OccurredAt` if you
   need the row. It is empty only if `crypto/rand` failed, in which case
   the event is delivered without it rather than dropped.

## Configuration the engine refuses

| Config | Error |
| --- | --- |
| `WebhookEvents` set, `Webhooks` nil | `ErrMissingWebhookSender` — a subscription to nowhere is a typo, not a feature |
| `WebhookEvents` containing `""` | `ErrInvalidWebhookEvent` — an empty type matches no event and would silently never fire |

An event type that is spelled wrong but non-empty (`"signup_sucess"`)
builds fine and is never delivered. There is no canonical list of the
engine's event types to validate against, and inventing one would put
the constants in two places that have to agree forever. The check that
catches this is your own: subscribe, do the thing, see the delivery.

## Running it

```
go test ./...
go run ./cmd/smoketest/webhooks
```

The smoke test is in-memory and makes no HTTP call. 75 checks over ten
sections:

1. **An event reaches the host app** — a signup delivers, and every
   field on the payload is the one the audit row got.
2. **Nothing configured, nothing changes** — no `Webhooks`, and the
   audit store the engine holds is the one you passed, undecorated.
3. **The default subset, one real operation at a time** — five distinct
   deliveries through the facade (signup, key created, key revoked,
   password changed, account deleted), plus `account_locked` from two
   wrong passwords at `LockoutThreshold: 2` and
   `token_reuse_detected` from a refresh token presented twice.
4. **What the default subset leaves out** — five logins, five refreshes
   and a logout deliver nothing at all, while all three stay in the
   audit log.
5. **An explicit subset takes exact control** — `[login_success]` alone
   delivers logins and nothing else; `append(DefaultWebhookEvents(),
   EventLoginSuccess)` delivers both.
6. **A broken sender costs the notification, never the operation** — a
   sender returning an error, then one that panics.
7. **The audit log is untouched by the filter** — unsubscribed events
   are still readable through `SearchByType`.
8. **Delivery IDs and the caller's context** — three deliveries, three
   distinct IDs, and the caller's trace ID readable inside
   `SendWebhook`.
9. **Configuration the engine refuses** — both errors above, plus the
   typo'd type that builds and never fires.
10. **What is actually delivered** — the printed payload of
    `signup_success` and `api_key_created`, and a check that no
    delivery anywhere contains the password.

## Trying it by hand

The shortest useful sender is a `log.Printf`:

```go
type printSender struct{}

func (printSender) SendWebhook(_ context.Context, e notify.WebhookEvent) error {
	log.Printf("%s user=%s ip=%s meta=%v", e.Type, e.UserID, e.IP, e.Metadata)
	return nil
}
```

Wire it, sign up, change the password, log in five times. You get two
lines, not seven — that is the default subset doing its job. Add
`store.EventLoginSuccess` to `WebhookEvents` and the logins appear.

Then break it on purpose: `return errors.New("queue down")`. The login
still succeeds and one Error line appears in the engine's log. Then
`panic("queue down")`, and watch the request die — rule 3 is not a
theoretical position.

## Postgres and SQLite

Nothing to run. This feature adds no table, no column and no migration —
it delivers events the audit table was already recording, and the audit
schema is unchanged. A host on Postgres and a host on SQLite wire it
identically.

## Known limits

- **No retries, no queue, no backoff, no dead-letter.** One call, one
  error, logged. Everything durable is the host's, which is the reason
  for the enqueue guidance in rule 1.
- **No signing.** The engine hands over a struct, not an HTTP request,
  so there is no HMAC header for it to compute. Whoever makes the call
  signs it.
- **At-most-once.** A process that dies between the audit write and the
  send loses the notification. The recovery path is the audit table:
  `SearchByType` from your last known timestamp.
- **No ordering guarantee.** Two concurrent operations deliver in
  whatever order they finish. `OccurredAt` is the field to sort on, at
  the platform's clock resolution.
- **Synchronous latency is real.** A sender taking 200ms adds 200ms to
  the login that triggered it. There is no engine-side goroutine, on
  purpose: an unbounded one is a memory leak under load, and a bounded
  one is a queue the host would rather own.
- **One sender, one filter.** No per-event routing, no per-tenant
  endpoint, no priority. `SendWebhook` branches on `Type` if you need
  that.
- **Only what the engine audits.** The filter can only ever be a subset
  of the audit event types; an event the engine does not record has
  nothing to deliver.
- **`Metadata` keys vary by event type** and are documented on the
  `store.AuditEventType` constants. Treat unknown keys as additive: a
  sender that switches on `Type` and reads the keys it knows keeps
  working when a new one appears.
- **No delivery of history.** Subscribing affects events from that
  moment on; the engine never replays what was recorded before.
