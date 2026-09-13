# cryden — progress log

Append-only. Newest entry at the bottom. One entry per session, added
right before that session stops — see `CLAUDE.md`'s end-of-session
checklist. Keep entries short: what got built, the branch, one line on
any assumption made. This is a log, not a design document — detailed
reasoning belongs in commit messages and code comments, not here.

---

## 2026 — Tier 1 (prior work, summarized retroactively)

Built across multiple sessions before this file existed: TOTP 2FA,
WebAuthn passkeys (second factor), magic-link login, OAuth provider-
agnostic confirmation (no engine changes needed for new providers),
recovery codes, breached-password checking, password policy. Plus a
fix for `LoginWithOAuth` bypassing the second-factor gate. Tagged as
**v2.2.0**. Full detail in each feature's git history and
`docs/testing/*.md` — not repeated here.

## 2026-09-03 — Development workflow setup

Added `CLAUDE.md` + this `docs/development/` structure
(`CURRENT-STATE.md`, `NEXT.md`, `CRYDEN-REVIEW.md`, `PROGRESS.md`) so
future terminal sessions read state from files instead of re-deriving
it through conversation each time. No engine code changed. Branch:
none — these are meta/process files, human will decide where they
land (likely directly reviewed and committed to whatever branch/main
state the human already has locally, since prior sessions' branches
were merged outside of this file-writing session).

---

<!-- New entries go below this line. -->

## 2026-09-04 — Anomaly detection (item 8)

Branch: `feat/anomaly-detection` (6 commits, unmerged, unpushed).

Built: report-only login anomaly detection. Pure threshold arithmetic
in `security/anomaly.go`, the storage-reading pass in
`auth/anomaly.go`, a `store.AnomalyStore` over a new `login_attempts`
table (memory + postgres + migration `0006`), an `anomaly_detected`
audit event, and `Config.Anomalies` / `Config.AnomalyThresholds`.
Detection is called once from `completePrimaryAuth`, which covers
password, magic-link and OAuth login together. 35 Go tests, a 54-check
smoke test at `cmd/smoketest/anomaly-detection`, and
`docs/testing/anomaly-detection.md`.

Assumptions made (spec left these open):

- **Config shape.** `NEXT.md` said "`Config.AnomalyDetector` or
  similar — you decide." I split it the way the codebase already
  splits this kind of thing rather than inventing a third pattern: an
  injected optional store (`Config.Anomalies`, nil ⇒ feature off, like
  `TOTP`/`WebAuthn`/`RecoveryCodes`) plus a plain config struct
  (`Config.AnomalyThresholds`, whole-struct zero ⇒ defaults, like
  `PasswordPolicy`). No detector interface: there is nothing here a
  host app would want to swap that the thresholds don't already cover,
  and an interface would have dragged `store` into `security`.
- **Six signals, not three.** The spec's "new IP/device" and "token
  reuse / session anomalies" each carry two distinct meanings, so each
  became two signals. A known device on a new IP is travel; a new
  device on a known IP is more often a second party. A replayed
  refresh token and an unusual live-session count are equally
  unrelated. Merging either pair would have made the metadata
  ambiguous for exactly the monitoring it exists to feed.
- **Baseline is successes only.** `AnomalyStore.ListRecentSuccesses`
  deliberately ignores failures. If failures fed the known-IP list, an
  attacker would establish their own address as familiar just by
  failing a few times first.
- **First login is never flagged.** `HasLoginHistory` suppresses
  new_ip/new_device when the account has no prior success. Otherwise
  every account's first login is an anomaly, which is noise.
- **A separate `TokenReuseLookback` (24h) alongside `Window` (15m).**
  Failure velocity is a burst happening now; a stolen refresh token
  replayed this morning still matters this afternoon. One duration
  could not serve both, and unbounded would flag every login the
  account ever makes again.
- **Token-reuse history is a bounded 100-event scan** of the user's
  audit log, because `AuditStore` has no by-user-and-type query
  (`ListByUser` is per-user, `SearchByType` is system-wide). A user
  with more than 100 events since their last reuse event misses the
  signal. Acceptable for a report-only annotation; adding an
  `AuditStore` method for it would have widened the item.
- **Sequencing.** Observations are read before the current attempt is
  recorded, so an attempt can never appear in its own baseline.
- **Storage errors degrade to "no evidence,"** never to "everything is
  unfamiliar" — the latter would flag every login during an outage.

Verification: `go build ./...`, `go vet ./...` and `go test ./...` all
run clean here with `GOTOOLCHAIN=go1.25.11 GOPROXY=off` (the module
cache has every dependency; only the toolchain download fails without
network, and `/usr/bin/go` is 1.22.2 while `go.mod` needs 1.25.0 —
hence the explicit `GOTOOLCHAIN`). The smoke test runs and passes all
54 checks. Postgres was not exercised — no database in this
environment; migration `0006` and `store/postgres/anomaly_store.go`
are reviewed-and-compiled only, and section 9 of the manual test guide
covers what to check against a real one.

Noted in passing, not fixed: `TestLogin_NonexistentUserTimingMatches`
`WrongPassword` in `auth/` is timing-based and flaked once when the
full suite ran packages in parallel (ratio 0.35), then passed on three
consecutive full runs and five isolated ones. Pre-existing and
unrelated to this item — it compares two bcrypt durations and is
sensitive to CPU contention. Worth its own small branch if it recurs.

Next in queue: item 9, credential-stuffing detection. `login_attempts`
already holds the data it needs; `NEXT.md` has the updated spec.
