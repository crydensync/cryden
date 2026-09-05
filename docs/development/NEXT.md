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

### 1. API keys / machine-to-machine auth (item 16)

New concept, not a variant of an existing one — no human to prompt, so
this sits outside the second-factor system entirely (confirm this
assumption is right by checking whether M2M auth appears anywhere else
in the codebase already — it shouldn't). Needs its own storage
(`store.APIKeyStore`), fast-hash lookup like recovery codes (SHA-256
via `token.HashToken`, not bcrypt — these are high-entropy generated
values, not human passwords), and its own facade functions
(`GenerateAPIKey`, `RevokeAPIKey`, and something that validates a
presented key and returns which user/scope it belongs to).

### 2. Webhooks (item 17)

Notify the host app on key events. Same question as everything else
that reaches outward: interface-only, zero shipped implementations
(`notify.WebhookSender` or similar), matching `EmailSender` — the
engine surfaces the event, the host app's implementation does the
actual HTTP call, retries, signing, etc. Decide which existing audit
events should also trigger a webhook call (probably a configurable
subset, not all of them) and wire it in wherever `audit.Record` is
already called for those events — don't build a second parallel event
bus.

### 3. Custom email templates (item 18)

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

### 4. Weekly digest (item 19)
Reads `AuditStore`, summarizes in plain English, returns text. Nothing
else.

### 5. Support-ticket assistant (item 20)
Read-only diagnosis ("why can't user X log in") — queries
`AuditStore`/`UserStore`/session state, produces an explanation, never
touches anything.

### 6. Config tuning advisor (item 21)
Produces a report of suggested config changes. Never applies them.

### 7. Ask-AI widget (item 22)
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
