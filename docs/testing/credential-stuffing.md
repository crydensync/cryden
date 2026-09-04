# Manual test guide — credential-stuffing detection

Credential stuffing is one IP trying one leaked password against many
different accounts. Per-account lockout structurally cannot see it:
lockout counts failures against *one* account, and a spray gives each
account exactly one failure. This feature reads the same
`login_attempts` history anomaly detection uses, but asks a different
question of it — not "how many attempts," but "how many different
targets."

Like anomaly detection, it is **report-only**. It never blocks a login,
never delays one, never forces step-up, and returns no error a caller
could branch on. Everything below is about what gets *recorded*.

The fastest full check is the smoke test:

```
go run ./cmd/smoketest/credential-stuffing
```

99 checks over seven scenarios, no database required. What follows is the
same ground covered by hand, plus the Postgres path the smoke test does
not touch.

## Setup

There is no separate on/off switch: `Anomalies` turns both detectors on,
because this is the same history read a second way, not a second
tracking system.

```go
engine, err := cryden.New(cryden.Config{
    JWTSecret: os.Getenv("CRYDEN_JWT_SECRET"),
    Users:     users,
    Sessions:  sessions,
    Audit:     audit,

    // Omit this and both detectors are entirely absent.
    Anomalies: postgres.NewAnomalyStore(db),

    // Omit this and security.DefaultCredentialStuffingThresholds
    // applies (1h window, 10 targets, 15m cooldown).
    CredentialStuffingThresholds: security.CredentialStuffingThresholds{
        Window:         time.Hour,
        TargetAccounts: 10,
        Cooldown:       15 * time.Minute,
    },
})
```

No migration is needed beyond `0006_login_attempts.up.sql` from anomaly
detection — the breadth query reads the same rows and the same partial
index (`idx_login_attempts_ip_failures`).

The two threshold structs default independently. Setting
`AnomalyThresholds` alone leaves credential-stuffing defaults in place,
and the reverse holds too — verify this if you tune either.

Test identity used throughout: `raymondproguy@dev.com` /
`Tr0ubl3-Fr33!2026`. Use a distinct wrong password for spray attempts so
the log reads like the attack it models.

## Reading the results

Every flagged address writes one `credential_stuffing_detected` audit
event:

```sql
SELECT created_at, user_id, ip, metadata
FROM audit_events
WHERE type = 'credential_stuffing_detected'
ORDER BY created_at DESC;
```

```
 metadata
------------------------------------------------------------------------
 {"signals": "account_spray", "distinct_accounts": "10",
  "unknown_targets": "0", "window": "1h0m0s"}
```

`user_id` is whichever account the *triggering* attempt named, and is
NULL when that attempt named an address with no account behind it. It is
incidental context — the subject of the event is the IP.

The breadth it measured can be read straight from the store:

```go
counts, _ := anomalies.CountTargetsForIP(ctx, "203.0.113.9", time.Now().Add(-time.Hour))
// counts.DistinctAccounts, counts.UnknownTargetFailures
```

## 1. A spray across real accounts

Register 10 accounts. With `TargetAccounts: 10`, submit one failed login
against each, all from one IP.

- Every attempt returns `ErrInvalidCredentials`, unchanged.
- Attempts 1–9 record **nothing**. The threshold is inclusive, so the
  tenth is the one that trips it.
- One event with `signals = "account_spray"`,
  `distinct_accounts = "10"`, `unknown_targets = "0"`.
- **No account is locked** — each saw a single failure, which is exactly
  why lockout cannot see this attack.

## 2. The same spray against addresses with no account

Submit `TargetAccounts` failed logins from one IP against emails that
were never registered (`nobody-1@dev.com` … ).

- The `login_attempts` rows land with `user_id IS NULL`.
- One event, `signals = "account_spray,unknown_account_spray"`,
  `distinct_accounts = "0"`, `unknown_targets = "10"`.
- The event's `user_id` is NULL.

`unknown_account_spray` is a qualifier, not a second bar — it never
fires alone. It says "most of this spray hit addresses that do not exist
here," which is what a list bought elsewhere looks like.

Unknown targets are counted as *attempts*, not distinct targets:
`store.LoginAttempt` deliberately never records which email was tried,
so there is nothing to de-duplicate on. Ten failures against the same
nonexistent address therefore count as ten. The default threshold leaves
headroom for that overcount; tighten `TargetAccounts` only if you have
measured your own traffic.

## 3. Hammering one account is NOT a spray

Submit 12 failed logins against a single existing account from one IP,
with `LockoutThreshold` raised above 12 so lockout does not fire first.

- **No** `credential_stuffing_detected` event, at any point.
- `CountFailuresForIP` returns 12; `CountTargetsForIP` returns
  `DistinctAccounts: 1`.

This is the case per-account lockout and anomaly detection's
`user_failure_velocity` already cover. Breadth is counted in distinct
targets precisely so this does not flag.

## 4. A login that succeeds from a spraying address

Run scenario 1 or 2, then log in legitimately from the same IP with the
correct password.

- **The login succeeds and returns normal tokens.** Verify this
  explicitly — it is the whole design.
- With `Cooldown: 0`, a second event is recorded whose `user_id` is the
  account that got in.

This is the most valuable signal the feature produces: a success from an
address currently spraying means one of the guesses landed. Detection
still does not block it — deciding what to do about it (force a password
reset, notify the owner, require step-up on the next request) is the
host app's call.

## 5. Cooldown

With `Cooldown: 15m`, keep spraying past the threshold — 20 or 30 more
attempts.

- Exactly **one** event, not one per attempt.
- Spray from a second IP: that address gets its own event. The cooldown
  is per-IP, because two addresses spraying at once are two incidents.

Set `Cooldown: 0` to record every crossing. Only do that if you are
feeding events to something that de-duplicates them itself — a sustained
spray writes one row per failed attempt otherwise.

Suppression is decided by scanning the 50 most recent
`credential_stuffing_detected` events. If more than 50 distinct IPs are
flagged inside one cooldown window, older ones fall off the scan and may
record a second event. A duplicate event is the deliberate failure
direction here; a missed attack is not.

## 6. Both off switches

Build an engine with `Anomalies` omitted and repeat scenario 1.

- Every login behaves exactly as it did before this feature existed.
- No events, and no `login_attempts` rows.

Then wire `Anomalies` but set `CredentialStuffingThresholds:
security.CredentialStuffingThresholds{}` (or just `TargetAccounts: 0`,
or `Window: 0`):

- No `credential_stuffing_detected` events.
- `anomaly_detected` events **still fire**. Silencing one detector must
  never disable the other.

## 7. Storage failure must not lock anyone out

Point `Anomalies` at a store whose queries fail (drop `login_attempts`,
or revoke access to it).

- Logins still succeed with valid credentials, and failures still return
  `ErrInvalidCredentials`.
- Errors appear in the log (`credential stuffing: ...`).
- No events. A failed read is "no evidence," never "flag everything."

A failing *audit* store degrades the same way: the cooldown check fails
open, so a repeat event may be written, but no login is affected.

## Known limits

- Detection is per-IP, so a spray distributed across a botnet — one
  attempt per address — is invisible to it. That is a different attack
  needing a different signal (per-account velocity across many IPs, or
  reputation data the engine has no source for).
- A large NAT or carrier gateway can legitimately produce failures
  against many accounts. The default 10-target/1-hour bar is set for
  that reality, and report-only is not a hedge here: blocking on this
  signal would take out every real user behind that address.
- The attempted email is not stored, by design. An event tells you an
  address was sprayed and how wide, not which addresses were tried.
- `memory.AnomalyStore` is for tests and local runs only. Two instances
  would each hold half the evidence and neither would see the pattern.
