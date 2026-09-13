# cryden — next up

Ordered queue. Take the **first item**, build it completely, then
stop — per `CLAUDE.md`. Remove an item from this file (or mark it done
— pick whichever this file's state already shows by the time you read
it) once it's finished and reflected in `CURRENT-STATE.md`.

Specs below are deliberately detailed so you don't need to ask
anything mid-build. Where something is genuinely unspecified, make the
most reasonable call consistent with `CRYDEN-REVIEW.md`'s established
patterns and note the assumption in `PROGRESS.md` — don't block on it.

---

Tier 3 is complete — all seven items done. See `CURRENT-STATE.md`.

---

## Tier 4 — AI-assisted admin features

**Non-negotiable for all four:** read-only / surface-only. No
automatic action — no auto-lock, no auto-config-change, nothing. Every
one of these produces information for a human to act on.

### 1. Weekly digest (item 19) — DONE
Built on `feat/weekly-digest`. `cryden.WeeklyDigest` /
`cryden.DigestSince`, new read-only `admin` package, new
`store.AuditStore.CountByType` on all three stores. See
`CURRENT-STATE.md`.

### 2. Support-ticket assistant (item 20) — DONE
Built on `feat/support-ticket-assistant`. `cryden.DiagnoseLoginIssue`,
new `admin.DiagnoseLogin` in the same read-only `admin` package item 19
started. See `CURRENT-STATE.md`.

### 3. Config tuning advisor (item 21) — DONE
Built on `feat/config-tuning-advisor`. `cryden.ConfigTuningReport` /
`cryden.TuningReportSince`, new `admin.BuildTuningReport` in the same
read-only `admin` package. See `CURRENT-STATE.md`.

### 4. Ask-AI widget (item 22) — DONE
Built on `feat/ask-ai-widget`. Design written first at
`docs/design/ask-ai-widget.md`. New `widget` package wrapping the
pre-existing `ai` package; one small additive export
(`ai.ExecuteIntent`) added to `ai` itself. See `CURRENT-STATE.md`.

Tier 4 is complete — all four items done. Do not proceed into Tier 5
without an explicit go-ahead from the project owner (see below and
`CURRENT-STATE.md`).

---

## Tier 5 — do not start

See `CURRENT-STATE.md`. Stop and say so if you reach here with nothing
else queued.
