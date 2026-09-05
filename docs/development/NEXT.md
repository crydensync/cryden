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

## Tier 3 — Infrastructure & Extensibility

### 1. Webhooks (item 17)

Notify the host app on key events. Same question as everything else
that reaches outward: interface-only, zero shipped implementations
(`notify.WebhookSender` or similar), matching `EmailSender` — the
engine surfaces the event, the host app's implementation does the
actual HTTP call, retries, signing, etc. Decide which existing audit
events should also trigger a webhook call (probably a configurable
subset, not all of them) and wire it in wherever `audit.Record` is
already called for those events — don't build a second parallel event
bus.

### 2. Custom email templates (item 18)

Check `notify.EmailSender`/`notify.MagicLinkSender` as they exist
today first — there's a real chance this needs **no engine change at
all**, since the host app's own implementation already owns the
actual email body/template (the engine only ever hands over a raw
token, per `EmailSender`'s own doc comment). If that's true, say so
plainly in `PROGRESS.md` and mark the item done-as-a-non-issue rather
than building something speculative to have built something.

---

## Tier 4 — AI-assisted admin features

**Non-negotiable for all four:** read-only / surface-only. No
automatic action — no auto-lock, no auto-config-change, nothing. Every
one of these produces information for a human to act on.

### 3. Weekly digest (item 19)
Reads `AuditStore`, summarizes in plain English, returns text. Nothing
else.

### 4. Support-ticket assistant (item 20)
Read-only diagnosis ("why can't user X log in") — queries
`AuditStore`/`UserStore`/session state, produces an explanation, never
touches anything.

### 5. Config tuning advisor (item 21)
Produces a report of suggested config changes. Never applies them.

### 6. Ask-AI widget (item 22)
The most complex of the four. Needs its own full design pass before
any code — at minimum: an LLM provider interface (zero shipped
implementations, host brings their own key/provider, same pattern as
every other external-network-call integration), a defined read-only
query surface, and an explicit answer to how untrusted end-user input
is kept from doing anything beyond reading data (this is exposed to
the host app's own end users, not just admins — prompt-injection
surface is real here). Write the design into this section of
`NEXT.md` (or a new file it points to) before writing any code, even
though there's no human to approve it mid-session — the design still
needs to exist and be reasoned through in writing, just do it as part
of this same session rather than waiting for a reply.

---

## Tier 5 — do not start

See `CURRENT-STATE.md`. Stop and say so if you reach here with nothing
else queued.
