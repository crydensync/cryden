# Manual test guide — login anomaly detection

Anomaly detection annotates successful logins that look unusual. It
**never blocks a login**, never returns a new error, and never forces
step-up authentication. Everything below is about what gets *recorded*.

The fastest full check is the smoke test:

```
go run ./cmd/smoketest/anomaly-detection
```

54 checks over six scenarios, no database required. What follows is the
same ground covered by hand, plus the Postgres path the smoke test does
not touch.

## Setup

The feature is off until you inject a store, exactly like TOTP and
recovery codes:

```go
engine, err := cryden.New(cryden.Config{
    JWTSecret: os.Getenv("CRYDEN_JWT_SECRET"),
    Users:     users,
    Sessions:  sessions,
    Audit:     audit,

    // Omit this and detection is entirely absent.
    Anomalies: postgres.NewAnomalyStore(db),

    // Omit this and security.DefaultAnomalyThresholds applies.
    AnomalyThresholds: security.AnomalyThresholds{
        Window:                15 * time.Minute,
        HistorySize:           20,
        UserFailureVelocity:   5,
        IPFailureVelocity:     20,
        MaxConcurrentSessions: 10,
        TokenReuseLookback:    24 * time.Hour,
    },
})
```

For Postgres, apply migration `0006_login_attempts.up.sql` first.

Test identity used throughout: `raymondproguy@dev.com` /
`Tr0ubl3-Fr33!2026`.

## Reading the results

Every flagged login writes one `anomaly_detected` audit event whose
metadata carries a comma-separated `signals` key, plus the count behind
each signal that fired:

```sql
SELECT created_at, ip, metadata
FROM audit_events
WHERE type = 'anomaly_detected' AND user_id = '<user-id>'
ORDER BY created_at DESC;
```

```
 metadata
-------------------------------------------------------------
 {"signals": "new_ip,new_device"}
 {"signals": "user_failure_velocity", "user_failures": "6"}
```

The raw history it judges against is in `login_attempts`:

```sql
SELECT created_at, user_id, ip, user_agent, outcome
FROM login_attempts
ORDER BY created_at DESC
LIMIT 20;
```

## 1. First login is clean

Sign up, then log in once.

- Login succeeds.
- **No** `anomaly_detected` event. A first login has no baseline to
  deviate from; flagging it would flag every new account.
- One `login_attempts` row with `outcome = 'success'`.

## 2. A familiar login stays quiet

Log in two or three more times from the same IP and User-Agent.

- No new `anomaly_detected` events.

This is the case that decides whether the feature is usable at all. If a
routine login flags, every login flags.

## 3. New IP and new device

Log in from a different IP with a different User-Agent.

- **The login succeeds and returns normal tokens.** Verify this
  explicitly — it is the whole design.
- One event, `signals = "new_ip,new_device"`.
- The event's `ip` is the new address.

Then log in from a third IP using the *original* User-Agent:

- `signals = "new_ip"` only. A known device on a new address is travel;
  a new device is a different claim, so the signals stay separate.

Log in from the second IP again:

- Nothing new. That address is now part of the baseline, because
  observations are gathered before the current attempt is recorded and
  the earlier attempt is now history.

## 4. Per-user failure velocity

With `UserFailureVelocity: 5` and `LockoutThreshold` raised above it (or
lockout will fire first and mask this), submit five wrong passwords, then
the correct one.

- The five failures each return `ErrInvalidCredentials`.
- Five `login_attempts` rows with `outcome = 'failure'`.
- The successful login is flagged: `signals = "user_failure_velocity"`,
  `user_failures = "5"`.

## 5. Per-IP failure velocity

Submit `IPFailureVelocity` failed attempts from one IP against an email
that has **no account** (`nobody@dev.com`), then log in legitimately from
that same IP.

- The rows land with `user_id IS NULL` — there is no user to attribute
  them to, and inventing one would be wrong.
- `CountFailuresForIP` counts them; `CountFailuresForUser` does not.
- The legitimate login is flagged `ip_failure_velocity`.

The per-IP threshold is deliberately much looser than the per-user one:
one office NAT or carrier gateway legitimately produces many users'
typos from a single address.

## 6. Token-reuse history

Trigger refresh-token reuse (send a refresh token twice — the second use
revokes the family and records `token_reuse_detected`), then log in.

- The login succeeds.
- `signals = "token_reuse"`, `token_reuse_events = "1"`.

Set `TokenReuseLookback` to something short and log in again: the signal
stops. One incident must not flag every login the account ever makes
again.

## 7. Concurrent sessions

With `MaxConcurrentSessions: 2`, log in four times without logging out.

- Logins 1–3 are quiet. Observations are read before the current
  attempt's own session exists, so login N sees N-1 active sessions —
  login 3 observes 2, which is at the limit, not over it.
- Login 4 observes 3 and is flagged `concurrent_sessions`,
  `active_sessions = "3"`.
- **No session is revoked.** Confirm with `cryden.ListSessions`.

## 8. Detection off

Build an engine with `Anomalies` omitted and repeat sections 1–3.

- Every login behaves exactly as it did before this feature existed.
- No `anomaly_detected` events, and no `login_attempts` rows.

## 9. Storage failure must not lock anyone out

Point `Anomalies` at a store whose queries fail (drop the
`login_attempts` table, or revoke access to it).

- Logins still succeed with valid credentials.
- Errors appear in the log (`anomaly: ...`).
- **No** `anomaly_detected` events. A failed read is treated as "no
  evidence," not as "everything is unfamiliar" — otherwise an outage
  would flag every login in it.

## Known limits

- Token-reuse history is found by scanning the user's 100 most recent
  audit events, because `AuditStore` has no by-user-and-type query. A
  user with more than 100 events since their last reuse event will not
  trip the signal. The reuse event itself is still in the audit trail.
- Impossible-travel and geo-velocity are deliberately out of scope: the
  engine never calls the internet, so it has no geo-IP source.
- `memory.AnomalyStore` is for tests and local runs only. Two instances
  would each hold half the evidence and neither would see the pattern.
