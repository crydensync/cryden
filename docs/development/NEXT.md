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

### 1. Anomaly detection (item 8) — design already decided, just build it

**Signals** (build all three, in one feature — they share the same
detection pass over a login attempt):
- **New IP/device**: compare the attempt's IP and User-Agent against
  the user's recent successful logins. Source: `AuditStore.ListByUser`
  and/or `SessionStore.ListByUser` — check both for whichever
  actually has the fields you need at low cost, don't guess, look at
  the real interfaces.
- **Failed-attempt velocity**: rate of `login_failed` events per user
  AND per IP over a configurable window, via `AuditStore.SearchByType`.
- **Token reuse / session anomalies**: escalate on
  `token_reuse_detected` events and unusually high concurrent-session
  counts for one user.

**On a flagged attempt**: record only, never block. New audit event
type(s) for the flag itself (e.g. `anomaly_detected` with a metadata
field describing which signal(s) fired) — do not add a new sentinel
error, do not force step-up 2FA, do not hard-block. This was
explicitly decided this way; do not revisit it.

**Storage**: new `store.AnomalyStore` interface + `store/memory` +
`store/postgres` implementations + migration. Design the interface
around "what does a caller need to query" (e.g. a user's recent known
IPs/devices, recent failed-attempt counts) rather than mirroring audit
events 1:1 — this store should make the detector's own reads cheap,
that's the whole reason it's not just more `AuditStore` queries.

**Where it plugs in**: this most likely runs as part of
`completePrimaryAuth` or right alongside it in `Login`/
`LoginWithOAuth`/`CompleteMagicLink` — after the primary factor is
confirmed, before (or in parallel with) the second-factor check. New
optional `Config.AnomalyDetector` (or similar — you decide the exact
field/interface split between "detection logic" and "storage," but
keep detection logic testable independent of storage, same as
everything else in this codebase). Fully additive — nil-safe, no
behavior change for an engine that doesn't configure it.

### 2. Credential-stuffing detection (item 9) — overlaps with item 8, don't duplicate

This is "many accounts failing from one IP" — which is *almost* the
same underlying data as item 8's per-IP failed-attempt velocity
signal. **Build the shared detection query once** (as part of item 8's
`AnomalyStore`, if item 8 is done first — check `CURRENT-STATE.md`).
This item's real incremental work is likely just: a distinct threshold
tuned for "one IP, many different target accounts" (existing per-
account lockout already handles "one account, many attempts" — this
is the gap that doesn't cover), and its own audit event type
(`credential_stuffing_detected`) so it's distinguishable from a
single-account anomaly in monitoring. If item 8 isn't built yet when
you reach this, build the minimal shared piece it needs rather than a
second parallel tracking system.

### 3. Named/fingerprinted sessions (item 10) — genuinely underspecified, use judgment

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

### 4. Redis-backed rate limiter (item 11)

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

### 5. Argon2id as an additional trusted hasher (item 12)

Second implementation of `security.Hasher`, not a replacement for
bcrypt. Real design question: how does the engine know which
algorithm a given stored hash used, for a user base that might have a
mix (e.g. mid-migration)? The common answer is sniffing the hash's own
format prefix (`$argon2id$...` vs bcrypt's `$2a$`/`$2b$`) inside a
dispatching `Compare`, while `Hash` always uses whichever algorithm is
currently configured. Build it this way unless you find a strong
reason not to; note the reasoning either way.

### 6. Additional storage backend beyond Postgres (item 13)

Every `store.X` interface already exists — implement all of them
against a second backend (SQLite is the most likely candidate per
earlier project notes, but check `CURRENT-STATE.md`/`PROGRESS.md` for
anything more specific by the time you get here). Watch for Postgres-
specific assumptions baked into existing interface docs/behavior
(`JSONB` columns, `ON CONFLICT ... DO UPDATE`, `RETURNING`) — several
`store/postgres/` implementations lean on these and a different
backend will need different real solutions, not just syntax swaps.

### 7. Cloud logger integrations (item 14)

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

### 8. Extensible JWT claims (item 15)

Let host apps attach their own data to access tokens. Read
`token/jwt.go`'s current claims struct and `JWTIssuer.Issue` before
proposing anything — whatever you add must not weaken the existing
algorithm-confusion protections already there (the `alg: none`/
signing-method check). Likely shape: `Issue` gains an optional
`extraClaims map[string]interface{}` parameter, or a small
`ClaimsProvider` hook — pick whichever fits the existing `Issue`
call sites with the least disruption.

### 9. API keys / machine-to-machine auth (item 16)

New concept, not a variant of an existing one — no human to prompt, so
this sits outside the second-factor system entirely (confirm this
assumption is right by checking whether M2M auth appears anywhere else
in the codebase already — it shouldn't). Needs its own storage
(`store.APIKeyStore`), fast-hash lookup like recovery codes (SHA-256
via `token.HashToken`, not bcrypt — these are high-entropy generated
values, not human passwords), and its own facade functions
(`GenerateAPIKey`, `RevokeAPIKey`, and something that validates a
presented key and returns which user/scope it belongs to).

### 10. Webhooks (item 17)

Notify the host app on key events. Same question as everything else
that reaches outward: interface-only, zero shipped implementations
(`notify.WebhookSender` or similar), matching `EmailSender` — the
engine surfaces the event, the host app's implementation does the
actual HTTP call, retries, signing, etc. Decide which existing audit
events should also trigger a webhook call (probably a configurable
subset, not all of them) and wire it in wherever `audit.Record` is
already called for those events — don't build a second parallel event
bus.

### 11. Custom email templates (item 18)

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

### 12. Weekly digest (item 19)
Reads `AuditStore`, summarizes in plain English, returns text. Nothing
else.

### 13. Support-ticket assistant (item 20)
Read-only diagnosis ("why can't user X log in") — queries
`AuditStore`/`UserStore`/session state, produces an explanation, never
touches anything.

### 14. Config tuning advisor (item 21)
Produces a report of suggested config changes. Never applies them.

### 15. Ask-AI widget (item 22)
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
