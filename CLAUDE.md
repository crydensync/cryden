# cryden — instructions for Claude Code

Read this file at the start of every session. It is the whole
protocol. Do not deviate to save credits — deviating IS what wastes
them.

## Startup — do exactly this, nothing more

1. Read `docs/development/CURRENT-STATE.md`.
2. Read `docs/development/NEXT.md`.
3. Pick the **first unstarted item** in `NEXT.md`. That is your only
   job this session.

Do not read anything else first. Do not "review the codebase to get
oriented." Do not open other branches to "see what's there." The two
files above ARE your orientation — they exist specifically so you
never have to rebuild it from scratch. If a specific implementation
detail in `docs/development/CRYDEN-REVIEW.md` is genuinely needed for
the item you're building, read that one file for that one section —
not the whole thing, not the whole source tree.

## Hard rules — no exceptions

- **Never use the Task tool, subagents, or any background/parallel
  worker.** One agent, one thread, one file at a time, foreground
  only. If you're about to spin up a helper to "work on this in
  parallel," stop — that's exactly the failure mode this file exists
  to prevent.
- **Never re-read a file you already read this session**, unless you
  just edited it and need to confirm the edit landed correctly.
- **Never re-verify or re-review a feature `NEXT.md`/`CURRENT-STATE.md`
  says is already done.** Done means done. Trust the files.
- **Build exactly one item per session, completely, then stop.** Don't
  chain into the next item in `NEXT.md` automatically. The human
  re-invokes you for the next one — that's the checkpoint, not a
  courtesy.
- **One git branch per item**, branched from the current tip of
  whatever you're on (check with `git branch --show-current` once,
  don't second-guess it after). Name it `feat/<item-slug>` or
  `fix/<item-slug>`.
- **Never merge to `main`. Never push, even if you have credentials
  configured.** The human reviews and pushes by hand, always.
- **Commit at every real step** (new interface, migration, wiring,
  tests, docs, smoke test) — not one giant commit at the end.
- **Commit messages: 5 lines maximum.** One summary line, optionally
  2-4 lines of real "why," nothing more. No essay-length commits.
- **Don't ask the human questions mid-task.** If `NEXT.md`'s spec for
  the item is ambiguous on some point, make the most reasonable
  engineering decision yourself, write one line about it in
  `PROGRESS.md`, and keep going. An unattended terminal run can't wait
  on an answer — deciding and noting it is strictly better than
  blocking.
- Every feature still gets: a `docs/testing/<item>.md` manual test
  guide, and a runnable in-memory smoke test at
  `cmd/smoketest/<item>/main.go` printing ✓/✗ per step, including
  negative cases. This hasn't changed from before.
- `gofmt -l` every changed file before each commit. Run `go build
  ./...` and `go test ./...` if your environment has real network/
  toolchain access; if it doesn't, say so plainly in `PROGRESS.md`
  rather than claiming untested code compiles.
- Standard placeholder identity in all examples/tests, unchanged:
  `raymondproguy@dev.com` / `Tr0ubl3-Fr33!2026`.

## Before you stop for the session

1. Update `docs/development/CURRENT-STATE.md` — move the item you
   built from "in progress"/"not started" to "done," name the branch.
2. Update `docs/development/NEXT.md` — remove the finished item (or
   mark it done, whichever the file's own convention is by then),
   leave the queue ready for the next invocation.
3. Append one short entry to `docs/development/PROGRESS.md` — date,
   item, branch, one line on what got built, one line on any
   assumption you made.
4. Commit those three doc updates together, one small commit,
   `docs:` prefix.
5. Print a short summary to the terminal: item built, branch name,
   what's next in the queue. Nothing else — no recap of the whole
   session, no restated plan.

That's the whole loop. Read state → build one thing → update state →
stop.
