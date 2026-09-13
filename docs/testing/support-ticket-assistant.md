# Manual test guide — Support-ticket assistant

A support ticket says "user X can't log in." Answering it today means
opening a database console, remembering which three or four tables
matter, and reading the account's own history by hand. `cryden.DiagnoseLoginIssue`
does that reading for you and hands back a paragraph:

```go
report, err := cryden.DiagnoseLoginIssue(ctx, engine, "someone@example.com")
if err != nil {
	return err
}
fmt.Println(report) // paste it straight into the ticket
```

That is the whole feature. It takes an engine and an email address,
returns a string, and does nothing else — no config field to set, no
store to supply. Like `WeeklyDigest`, it belongs to Tier 4's
non-negotiable rule: read-only, structurally so. `admin.DiagnoseLogin`
is handed three narrow interfaces (`UserByEmailReader`,
`UserAuditHistoryReader`, `UserSessionReader`), none of which has a
`Create`, `LockAccount`, `ResetFailedAttempts` or `Revoke` on it — a
diagnosis cannot unlock the very account it is reporting on, because it
is never handed anything that could.

## The shape

| Piece | Where | What it is |
| --- | --- | --- |
| `cryden.DiagnoseLoginIssue(ctx, e, email)` | `cryden.go` | The report, as text |
| `admin.DiagnoseLogin` | `admin/support.go` | The structured `LoginDiagnosis` behind the text |
| `admin.UserByEmailReader` | `admin/support.go` | The read-only slice of `store.UserStore` used |
| `admin.UserAuditHistoryReader` | `admin/support.go` | The read-only slice of `store.AuditStore` used |
| `admin.UserSessionReader` | `admin/support.go` | The read-only slice of `store.SessionStore` used |

## What it looks like

An account mid-lockout:

```
Login diagnosis for raymondproguy@dev.com

Account is LOCKED until 5 Sep 2026 23:44 UTC.
5 consecutive failed attempts currently recorded (resets on the next successful sign-in).
0 sessions are currently active.

Recent failure-type events (6 events, newest first):
  5 Sep 23:29 UTC — user 01a073e7-dbf9-7d7e-8bfd-a4b40648abf4, IP 198.51.100.7 — account_locked
  5 Sep 23:29 UTC — user 01a073e7-dbf9-7d7e-8bfd-a4b40648abf4, IP 198.51.100.7 — login_failed
  5 Sep 23:28 UTC — user 01a073e7-dbf9-7d7e-8bfd-a4b40648abf4, IP 198.51.100.7 — login_failed
  ...

Most recent event of any kind: 5 Sep 23:29 UTC — ... — account_locked.
```

An account with no problem visible in its own history:

```
Login diagnosis for ok@example.com

Account is not locked.
0 consecutive failed attempts currently recorded (resets on the next successful sign-in).
1 session is currently active.

No recent failure-type events in this account's history.

Most recent event of any kind: 5 Sep 23:29 UTC — ... — login_success.
```

An email with no account behind it:

```
Login diagnosis for nobody@example.com

No account exists for this email address.
```

That last case is deliberately not an error. "No such account" is
itself the answer a support ticket asked for.

## What it checks, in order

1. **Does the account exist at all?** A typo'd email, a deleted
   account, or somebody asking about the wrong email address are all
   the same finding: no account, nothing more to check.
2. **Is it locked right now?** `User.LockedUntil` is read directly and
   compared against the current time — a lock that expired an hour ago
   is reported as *not* locked, because it no longer explains anything.
3. **How many failed attempts are on the counter right now?**
   `User.FailedAttempts` — the number that determines how close the
   account is to (or how it got to) a lockout.
4. **How many sessions does it hold right now?** Zero active sessions
   alongside a recent `login_success` usually means "signed out since,"
   not "can't sign in" — the report doesn't draw that conclusion for
   you, but it gives you the number.
5. **What does its own recent history say?** Up to the last 100 events
   for that account (`admin.diagnosisHistoryLimit`), filtered down to
   the failure-shaped ones — `login_failed`, `account_locked`,
   `totp_challenge_failed`, `webauthn_challenge_failed`,
   `recovery_code_failed`, `anomaly_detected`,
   `credential_stuffing_detected` — newest first. A successful sign-in
   in that same window is real history and is *not* listed here; it
   would bury the failures a support agent is looking for.

## What it will never tell you

This reads what the engine itself recorded. It has no visibility into:

- A client-side problem (wrong password typed, autofill filling in an
  old one, a broken build of the app).
- An upstream OAuth provider being down or misconfigured — `LoginWithOAuth`
  records the same audit events as every other primary auth path, but
  a provider-side outage before the request ever reaches cryden leaves
  no trace here.
- Network issues between the user and your servers.

If the diagnosis comes back with nothing but "not locked, no recent
failures, one session active," the most likely explanation is outside
what this can see — which is itself useful information for a support
agent deciding where to look next.

## Manually verifying read-only behaviour

The property worth checking by hand, not just in the smoke test:

1. Lock an account (five wrong passwords against a fresh account, with
   default settings).
2. Run `DiagnoseLoginIssue` against it several times in a row.
3. Confirm the account is still locked afterward, for exactly as long
   as it would have been anyway — the lockout timer didn't reset, and
   `FailedAttempts` didn't move. Reading the diagnosis is exactly like
   not reading it, from the account's point of view.

## Running the smoke test

```
go run ./cmd/smoketest/support-ticket-assistant
```

No database required — everything runs against `store/memory`. Covers:
an unknown email, a locked account with a full failure history and a
verified-stable second read, a healthy account, a read-only check that
runs the diagnosis five times and confirms nothing on the account
moved, and a check that neither the password nor the JWT secret ever
appear in the rendered text.
