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
