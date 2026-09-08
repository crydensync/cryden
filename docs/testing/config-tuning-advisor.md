# Manual test guide — Config tuning advisor

```go
report, err := cryden.ConfigTuningReport(ctx, engine)
if err != nil {
	return err
}
fmt.Println(report)
```

Reads the last 30 days of audit history (`admin.DefaultTuningWindow`)
against the engine's own current settings, and returns a list of
suggested changes as text. `TuningReportSince(ctx, engine, since)` picks
a different window, the same relationship `DigestSince` has to
`WeeklyDigest`.

**It never applies anything.** There is no config-mutation path in this
feature at all — not a partial one, not one gated behind a flag. It
reads `Config.LockoutThreshold`, `RateLimitAttempts`, whether
`Anomalies`/`BreachedPasswordChecker` are configured, and 30 days of
`AuditStore.CountByType`, and turns that into prose. A human reads the
prose and edits their own `Config` if they agree.

## The shape

| Piece | Where | What it is |
| --- | --- | --- |
| `cryden.ConfigTuningReport(ctx, e)` / `TuningReportSince` | `cryden.go` | The report, as text |
| `admin.BuildTuningReport` | `admin/tuning.go` | The structured `TuningReport` behind the text |
| `admin.TuningInputs` | `admin/tuning.go` | A plain-data snapshot of the engine's settings — not `security`'s own config structs, so this package doesn't need to import `security` for six numbers and three booleans |
| `admin.AuditReader` | `admin/digest.go` | The same read-only interface `BuildDigest` uses — `CountByType` only; a tuning report never calls `SearchByType` |

## What it checks, and what each one means if it fires

**Lockout.** Fires only when at least 3 `account_locked` events occurred
*and* they're at least 10% of `login_failed` events in the window. Both
conditions exist to avoid noise: a 2-lockout weekend on a quiet app can
easily be a 50% ratio and mean nothing. If most of those lockouts look
like ordinary typos rather than an attack, the suggestion is to raise
`LockoutThreshold` and/or shorten `LockoutDuration`.

**Rate limiting.** Fires whenever `Config.RateLimiter` was left unset —
which means the in-process default is running, and its counters live in
one process's memory. This one needs no audit data at all; it's a fact
about the deployment, not the traffic, and it repeats a caveat that's
already documented directly on `Config.RateLimiter`.

**Anomaly detection**, three distinct findings depending on state:
- `Config.Anomalies` unset → detection isn't running at all; informational, no urgency.
- Configured, but flagged nothing despite ≥50 successful sign-ins in
  the window → may be a quiet window, may be loose thresholds; the
  report says both possibilities rather than picking one.
- Configured, and ≥20% of successful sign-ins were flagged → thresholds
  may be tighter than this population needs (shared office egress,
  frequent travel), or the flags may be real. Same non-committal
  framing.

**Credential stuffing.** Only has something to say when a burst was
actually detected in the window — there's no "suspiciously quiet"
finding here, because that would just restate the anomaly-detection
silence finding under a different name.

**Password strength.** The one area where a finding can be good news:
if `BreachedPasswordChecker` is configured and it rejected passwords
this window, the report says so and explicitly suggests no change —
the feature is working. If it isn't configured at all, the report notes
it's a strictly additive, fail-open protection with no downside to
turning on.

## What a report looks like

A quiet, mostly-default deployment:

```
Config tuning report — 9 Aug 2026 02:17 UTC to 8 Sep 2026 02:17 UTC (30 days)

Rate limiting
  Using the default in-memory rate limiter (10 attempts per 1m0s).
  → This keeps its counters in one process's memory. Running more than one instance behind a load balancer means each replica counts independently, so the effective limit is (instances × RateLimitAttempts). If this deployment runs more than one instance, consider security.NewRedisRateLimiter for a shared limiter.

Anomaly detection
  Config.Anomalies is not set, so no login is screened for new-IP, new-device, failure-velocity, or session-count signals.
  → Report-only and off by default — consider enabling it (a store.AnomalyStore) if this deployment wants that visibility. Nothing about login behavior changes when it's on; a flagged attempt is still let through.

Password strength
  Config.BreachedPasswordChecker is not set.
  → Checked only on SignUp/ChangePassword when configured, and fails open on error, so it is a strictly additive protection with no downside to enabling.
```

A window with nothing worth flagging:

```
Config tuning report — 9 Aug 2026 02:17 UTC to 8 Sep 2026 02:17 UTC (30 days)

Nothing stands out against current settings in this window.
```

## Running the smoke test

```
go run ./cmd/smoketest/config-tuning-advisor
```

No database required — everything runs against `store/memory`. Covers:
a default configuration (flags the unconfigured rate limiter, anomaly
detection, and breach checker; does *not* flag credential stuffing
since anomaly detection is off), a fully-configured `Anomalies` store
(confirms the disabled-anomaly finding disappears), four accounts
locked out to clear the lockout heuristic's floor, and three
back-to-back reads confirming the suggestion set doesn't move against
unchanged history.
