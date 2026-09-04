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

## Tier 2 — Security & Monitoring

### 1. Named/fingerprinted sessions (item 10) — genuinely underspecified, use judgment

Current `store.Session` already has `IP` and `UserAgent`. "Named/
fingerprinted" most likely means: a human-readable label for "your
active sessions" UI (e.g. "Chrome on Windows — San Francisco, CA")
instead of a raw session ID.

- User-Agent → device/browser string: pure parsing, no network call,
  no external API — fine to ship as a real engine-side helper (or a
  small interface if you think host apps would want to swap parsing
  libraries; use your judgment, this is a minor decision either way).
- IP → location string: this DOES require geolocation data from
  somewhere. Follow the established rule — if it needs an outbound
  network call, it's a new interface (e.g. `security.IPGeolocator`)
  with **zero shipped implementations**, host supplies one, exactly
  like `BreachedPasswordChecker`. Do not bake in a call to any
  specific geo-IP service directly.
- If geolocation feels like it belongs entirely at the `api`/host-app
  layer instead of the engine (since the engine already exposes raw
  IP on every session), that's a legitimate alternative — note your
  reasoning in `PROGRESS.md` either way, this is the item where the
  original backlog line is vaguest and a documented judgment call is
  expected.

### 2. Redis-backed rate limiter (item 11)

`security.RateLimiter` already exists with one implementation
(in-memory, documented as not safe across multiple instances). This is
a **second real implementation**, not an interface-only integration —
Redis is configured infrastructure the host app wires in explicitly
(a connection string/client), the same category as Postgres, not an
arbitrary third-party internet service like HIBP. Ship a real
`security.RedisRateLimiter` (or wherever you decide it should live —
probably `security/`, matching where the in-memory one lives) using a
real, well-established Go Redis client library. `Config` gets a new
way to select/configure it (follow how `Users`/`Sessions`/etc. stores
are injected as already-constructed instances, not built internally
from a connection string — match that pattern here too).

---

## Tier 3 — Infrastructure & Extensibility

### 3. Argon2id as an additional trusted hasher (item 12)

Second implementation of `security.Hasher`, not a replacement for
bcrypt. Real design question: how does the engine know which
algorithm a given stored hash used, for a user base that might have a
mix (e.g. mid-migration)? The common answer is sniffing the hash's own
format prefix (`$argon2id$...` vs bcrypt's `$2a$`/`$2b$`) inside a
dispatching `Compare`, while `Hash` always uses whichever algorithm is
currently configured. Build it this way unless you find a strong
reason not to; note the reasoning either way.

### 4. Additional storage backend beyond Postgres (item 13)

Every `store.X` interface already exists — implement all of them
against a second backend (SQLite is the most likely candidate per
earlier project notes, but check `CURRENT-STATE.md`/`PROGRESS.md` for
anything more specific by the time you get here). Watch for Postgres-
specific assumptions baked into existing interface docs/behavior
(`JSONB` columns, `ON CONFLICT ... DO UPDATE`, `RETURNING`) — several
`store/postgres/` implementations lean on these and a different
backend will need different real solutions, not just syntax swaps.

### 5. Cloud logger integrations (item 14)

`logger.Logger` already exists with one implementation (console JSON).
Decide interface-only-vs-shipped-implementation the same way as
everything else: does using this necessarily mean an outbound network
call? If yes (calling Datadog's/Better Stack's API directly), lean
toward interface-only, zero shipped implementations — most host apps
already have their own logging pipeline wired at their level, and
console-JSON-to-stdout is already the universal integration point
(any log shipper can tail stdout). Only ship a real implementation if
there's a specific strong reason a direct integration adds real value
over "the host app already captures stdout."

### 6. Extensible JWT claims (item 15)

Let host apps attach their own data to access tokens. Read
`token/jwt.go`'s current claims struct and `JWTIssuer.Issue` before
proposing anything — whatever you add must not weaken the existing
algorithm-confusion protections already there (the `alg: none`/
signing-method check). Likely shape: `Issue` gains an optional
`extraClaims map[string]interface{}` parameter, or a small
`ClaimsProvider` hook — pick whichever fits the existing `Issue`
call sites with the least disruption.

### 7. API keys / machine-to-machine auth (item 16)

New concept, not a variant of an existing one — no human to prompt, so
this sits outside the second-factor system entirely (confirm this
assumption is right by checking whether M2M auth appears anywhere else
in the codebase already — it shouldn't). Needs its own storage
(`store.APIKeyStore`), fast-hash lookup like recovery codes (SHA-256
via `token.HashToken`, not bcrypt — these are high-entropy generated
values, not human passwords), and its own facade functions
(`GenerateAPIKey`, `RevokeAPIKey`, and something that validates a
presented key and returns which user/scope it belongs to).

### 8. Webhooks (item 17)

Notify the host app on key events. Same question as everything else
that reaches outward: interface-only, zero shipped implementations
(`notify.WebhookSender` or similar), matching `EmailSender` — the
engine surfaces the event, the host app's implementation does the
actual HTTP call, retries, signing, etc. Decide which existing audit
events should also trigger a webhook call (probably a configurable
subset, not all of them) and wire it in wherever `audit.Record` is
already called for those events — don't build a second parallel event
bus.

### 9. Custom email templates (item 18)

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

### 10. Weekly digest (item 19)
Reads `AuditStore`, summarizes in plain English, returns text. Nothing
else.

### 11. Support-ticket assistant (item 20)
Read-only diagnosis ("why can't user X log in") — queries
`AuditStore`/`UserStore`/session state, produces an explanation, never
touches anything.

### 12. Config tuning advisor (item 21)
Produces a report of suggested config changes. Never applies them.

### 13. Ask-AI widget (item 22)
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
