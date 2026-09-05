# Manual test guide — Weekly digest

The engine has recorded everything worth knowing for a long time: every
sign-in, every lockout, every reused refresh token, every API key
presented after revocation. It went into the audit table, and there it
stayed. Reading it meant knowing which of 31 event types mattered,
writing the SQL, and remembering to do it — so in practice nobody did,
and the table people built for exactly this purpose went unread.

`cryden.WeeklyDigest` reads it for you and hands back a paragraph:

```go
report, err := cryden.WeeklyDigest(ctx, engine)
if err != nil {
	return err
}
fmt.Println(report) // or mail it, or post it to Slack
```

That is the whole feature. It takes an engine, returns a string, and
does nothing else — no config field to set, no store to supply, no
option to tune. Everything below is what to know before you put it on a
schedule.

## The shape

| Piece | Where | What it is |
| --- | --- | --- |
| `cryden.WeeklyDigest(ctx, e)` | `cryden.go` | The last seven days, as text |
| `cryden.DigestSince(ctx, e, since)` | `cryden.go` | The same report over a window you choose |
| `admin.DefaultDigestWindow` | `admin/digest.go` | `7 * 24 * time.Hour` |
| `admin.BuildDigest` | `admin/digest.go` | The structured `Digest` behind the text, if you want the numbers |
| `admin.AuditReader` | `admin/digest.go` | The read-only slice of `store.AuditStore` a report is given |
| `store.AuditStore.CountByType` | `store/interfaces.go` | New method: per-type counts over a window, counted in the database |

`admin` is a new package, and the naming is deliberate: it holds the
read-only reporting surface, and every read in it goes through an
interface with no `Write` and no `Record` on it. A report structurally
cannot lock an account or record an event of its own — not by
convention, by not being handed anything that could.

## What it looks like

```
Security digest — 29 Aug 2026 23:29 UTC to 5 Sep 2026 23:29 UTC (7 days)
8 events recorded in total.

Needs attention
  1 account was locked after repeated failed sign-ins
    5 Sep 23:29 UTC — user 01a073e7-dbf9-7d7e-8bfd-a4b40648abf4, IP 198.51.100.7

Accounts
  1 account was created

Sign-ins
  1 sign-in succeeded
  5 sign-in attempts failed
```

Sections print in a fixed order — `Needs attention`, `Accounts`,
`Sign-ins`, `Sign-in methods`, `API keys`, then `Other events` — so what
needs a human is at the top and routine volume is at the bottom. A
section with nothing in it is left out entirely, and so is any event type
with no events, which is what keeps a quiet week to two lines instead of
a page of zeroes.

Only the four `Needs attention` types get their individual events spelled
out underneath the count: `account_locked`, `token_reuse_detected`,
`anomaly_detected`, `credential_stuffing_detected`. Everything else is
counted. Listing 4,210 successful sign-ins would bury the one lockout
that mattered.

## Run the checks

```bash
go run ./cmd/smoketest/weekly-digest   # ✓/✗ per step, prints a real report
go test ./admin/ -v                    # building and rendering, no engine
go test . -run Digest -v               # through the real facade and engine
```

The smoke test prints an actual digest partway through, which is the
fastest way to see what your own report will look like.

## Manual test

The digest reads whatever is in your audit store, so the manual test is:
make some history, then read it back.

1. **Start from nothing.** Build an engine on empty stores and call
   `cryden.WeeklyDigest`. You should get the header and
   `Nothing to report: no audit events were recorded in this window.`
   and nothing else. A digest that prints a wall of zeroes for a quiet
   week stops being read by week three; this is the check that it does
   not.

2. **Sign one account up, sign in once.** Call the digest again. You
   should see `Accounts` with `1 account was created` and `Sign-ins`
   with `1 sign-in succeeded`. Note the singular — the phrases carry
   their own verb, so counts of one read as English rather than
   `1 accounts were created`.

3. **Get an account locked.** Sign in with the wrong password five times
   (the default `LockoutThreshold`). The digest now opens with
   `Needs attention`, and the lockout has a line under it with the
   timestamp, the user ID and the IP that caused it. This is the one
   thing a digest does that a count cannot: it tells you *which*
   account, so you can go look.

4. **Check the total.** The `N events recorded in total` line is the sum
   of every type, including ones no section names. After steps 2 and 3
   it should be 8: one signup, one good sign-in, five failures, one
   lockout.

5. **Lock more than ten accounts.** The count stays exact and the detail
   is capped: `12 accounts were locked …` followed by ten lines and
   `(the 10 most recent of 12 shown)`. The cap bounds how much a digest
   prints, never what it knows — the number beside the heading is always
   the real one.

6. **Record one of your own event types.** Write into the same audit
   store you handed the engine:

   ```go
   audit.Record(ctx, store.AuditEvent{Type: "acme_invoice_paid", UserID: id})
   ```

   It shows up under `Other events (types this engine does not define)`
   with an exact count. Your events are not dropped for being unknown,
   and neither are any the engine gains after this report was written —
   a stale section table degrades a digest, it does not hide anything
   from it.

7. **Read it twice.** Two consecutive digests of the same history are
   byte-identical below the header line (the header's end time is a
   clock read). Building a report records nothing, so nothing about your
   audit history changes by looking at it.

## If you implement `store.AuditStore` yourself

This item added a method to the interface:

```go
CountByType(ctx context.Context, since time.Time) (map[AuditEventType]int, error)
```

All three shipped stores — `memory`, `postgres`, `sqlite` — have it. A
host with its own implementation will not compile until it does too, and
that is the intended failure: a silently missing count would mean a
digest reporting a quiet week because the store could not answer.

The contract, in full:

- Count every event recorded **at or after** `since`. The boundary
  instant is inside the window.
- A type with no events in the window is **absent from the map**, not
  present with a zero. That is how a report tells "nothing happened"
  apart from "this type does not exist here".
- An empty window returns an **empty non-nil map**, never an error.
- Count types you do not recognise. Do not validate against the engine's
  list — a host's own event types live in the same table and must be
  counted, not dropped.

Count in the database if you can. The point of the method is that no
audit row travels over the network to be counted: `SELECT type,
COUNT(*) … WHERE created_at >= $1 GROUP BY type` is one round trip, and
a digest that pulled rows to call `len()` on them would move a week of
sign-ins to print one number.

## Before you schedule it

**It is a read, so put it behind an admin route or a cron job, not a
public one.** The report names user IDs and IP addresses. It contains no
password, no hash, no token and no secret — the smoke test checks all
four — but it is internal information, and it is a full table scan.

**Postgres has no index for this.** Neither `(created_at)` nor
`(type, created_at)` exists on `audit_events`, so this is a sequential
scan — the same trade the schema already documents for `SearchByType`.
That is affordable weekly and wrong per-request: an extra B-tree on the
busiest write path in the database is not something you undo cheaply, so
if you want this hourly, add the index deliberately rather than assuming
one is there.

**The window always ends now.** `DigestSince` takes a start and reports
up to the present. There is no historical-slice read behind it, because
the detail rows come from `SearchByType`, which returns the newest events
of a type and nothing else — a window ending last Tuesday would count
correctly and come back with no detail at all. A `since` in the future is
not an error; it is an empty window, and the report says so.

**Everything is printed in UTC**, whatever the machine's zone, so the
same digest reads the same from a cron container and a laptop.

**Errors are errors.** If the store cannot answer, `WeeklyDigest`
returns the error and no text. It never degrades into a report that looks
like a calm week — that failure mode would be worse than no digest at
all, and the smoke test covers both halves of it (counts failing, and
detail failing while counts work).
