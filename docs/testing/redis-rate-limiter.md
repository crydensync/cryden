# Manual test guide — Redis-backed rate limiter

The rate limiter that ships by default keeps its counters in a Go map.
That is correct for exactly one process. Run three replicas behind a
load balancer and each keeps its own map, so a configured limit of 10
lets 30 through — and an attacker doesn't have to know that to benefit
from it, the load balancer spreads their attempts for them.

`security.RedisRateLimiter` moves the counters to Redis so every replica
counts against one window. It is a **real second implementation of the
same `security.RateLimiter` interface**, not a new hook: `Allow` is the
whole surface, and nothing in `auth/` can tell which one it holds.

The fastest full check is the smoke test:

```
go run ./cmd/smoketest/redis-rate-limiter
```

58 checks over ten scenarios, no Redis server and no database required —
it runs against an in-process stand-in that models what Redis does with
the script.

That stand-in is a model, so it proves the Go side and **not Redis's own
execution of the Lua**. To close that gap, point the same smoke test at
a real server:

```
docker run --rm -d -p 6379:6379 --name cryden-redis redis:7-alpine
REDIS_ADDR=127.0.0.1:6379 go run ./cmd/smoketest/redis-rate-limiter
docker rm -f cryden-redis
```

Identical output, except the two scenarios that need to break Redis or
count round trips from the inside, which report as skipped. An
unreachable `REDIS_ADDR` is a hard stop, never a silent fallback to the
stand-in — a green run is always a green run of the mode you asked for.
Keys are namespaced per run and deleted afterwards, so it is safe
against a Redis you also use for something else.

## Setup

The client is injected already constructed, the same as every store —
the engine never dials Redis, never reconnects it and never closes it:

```go
rdb := redis.NewClient(&redis.Options{
    Addr:     os.Getenv("REDIS_ADDR"),
    Password: os.Getenv("REDIS_PASSWORD"),
})
defer rdb.Close()

limiter, err := security.NewRedisRateLimiter(rdb, 10, time.Minute)
if err != nil {
    log.Fatal(err)
}

engine, err := cryden.New(cryden.Config{
    JWTSecret:   os.Getenv("CRYDEN_JWT_SECRET"),
    Users:       users,
    Sessions:    sessions,
    Audit:       audit,
    RateLimiter: limiter,
})
```

`RateLimitAttempts` and `RateLimitWindow` are ignored once
`RateLimiter` is set — they are the in-memory limiter's constructor
arguments, and a limiter you built already carries its own bounds. Leave
`RateLimiter` nil and nothing changes from previous versions.

`*redis.Client`, `*redis.ClusterClient`, `*redis.Ring` and
`redis.UniversalClient` are all accepted: the parameter is
`redis.Scripter`, go-redis's own interface, so a fake is easy to write
and Cluster needs no special case (one `Allow` touches exactly one key,
so the script never spans slots).

Constructor arguments are validated, because there is no
`Config.applyDefaults` between you and it:

| Argument | Rejected with |
|---|---|
| `nil` client | `security.ErrNilRedisClient` |
| `limit <= 0` | `security.ErrInvalidRateLimit` |
| `window < time.Millisecond` | `security.ErrInvalidRateWindow` |

The millisecond floor is the **one** place the two implementations are
not interchangeable: `PEXPIRE` cannot express a shorter window, and
rounding a 500µs window up to 1ms silently would be worse than saying
so.

## 1. The limit itself

With a limit of 3 and a one-minute window, call `Allow` five times with
the same key:

```
true true true false false
```

Calls 1–3 pass, 4 and 5 are denied. A different key is unaffected —
counters are per key, and keys are opaque strings the caller builds.

## 2. The window is fixed, not sliding

Take the limit, then keep hammering. When the window ends, the counter
resets **on its original schedule** — the denied calls do not push it
out.

This is worth checking deliberately, because the obvious
implementation gets it wrong. Arming the expiry on every call (rather
than only on the call that creates the counter) turns a blocked
client's own retries into a permanently blocked key: every retry
extends the window it is waiting on. The Lua arms `PEXPIRE` when
`INCR` returns 1, and otherwise only when `PTTL` reports no expiry at
all.

## 3. Two replicas share one window

The reason the feature exists. Build **two** limiters over the same
Redis, limit 2, and alternate:

```
A.Allow(key) -> true
B.Allow(key) -> true
A.Allow(key) -> false
B.Allow(key) -> false
```

Two in total, not two each. Do the same with two engines on the
in-process default and a limit of 1, and both let a signup through —
that contrast is the bug this fixes.

## 4. Through the engine

Nothing about the call sites changed. With a limit of 1:

```go
cryden.SignUp(ctx, engine, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4")  // ok
cryden.SignUp(ctx, engine, "raymondproguy@dev.com", "Tr0ubl3-Fr33!2026", "1.2.3.4")  // auth.ErrRateLimited
```

The second returns `auth.ErrRateLimited` **before touching the user
store**. Logging in still works right after, because the three call
sites use different keys:

| Call | Key |
|---|---|
| `SignUp` | `signup:<ip>` |
| `Login` | `login:<ip>:<email>` |
| `RequestMagicLink` | `magic-link:<ip>:<email>` |

Those keys get the prefix `cryden:ratelimit:` in Redis, so
`cryden:ratelimit:signup:1.2.3.4`. Check with `redis-cli --scan --pattern
'cryden:ratelimit:*'` while attempts are in flight, and `PTTL` on one of
them to watch the window count down.

## 5. Keys are namespaced

The prefix exists so a counter can never land on a key your app already
owns. `security.NewRedisRateLimiterWithPrefix` overrides it — useful to
separate staging from production on one Redis, since a different prefix
is a different window:

```go
security.NewRedisRateLimiterWithPrefix(rdb, 10, time.Minute, "myapp:staging:rl:")
```

An empty prefix is legal and means raw, unprefixed keys. Verify that
what you expect is what exists: with the default prefix, `EXISTS
signup:1.2.3.4` must be 0 and `EXISTS cryden:ratelimit:signup:1.2.3.4`
must be 1.

## 6. Redis going down blocks logins — on purpose

**The important negative case, and the one thing to decide before
deploying this.** Stop Redis and try to log in:

```
docker stop cryden-redis
```

The login fails with the wrapped Redis error — not
`auth.ErrRateLimited`, so a caller branching on that sentinel still
tells the two apart:

```
security: redis rate limiter: dial tcp 127.0.0.1:6379: connect: connection refused
```

`Allow` returns `(false, err)`, and all three call sites propagate it.
So wiring Redis in makes it a **hard dependency of SignUp, Login and
RequestMagicLink**. That is the deliberate choice — failing open on a
limiter outage means an unlimited credential-stuffing window that
starts exactly when your monitoring is already busy — but it is a
choice, and the availability cost is real.

To trade it the other way, wrap the limiter in your own type. The
engine holds an interface, so this needs no engine change:

```go
type failOpen struct{ inner security.RateLimiter }

func (f failOpen) Allow(ctx context.Context, key string) (bool, error) {
    allowed, err := f.inner.Allow(ctx, key)
    if err != nil {
        // Prefer serving traffic to enforcing the limit. Alert on this.
        return true, nil
    }
    return allowed, nil
}
```

Start Redis again and confirm logins recover immediately — the limiter
holds no broken state, it only asks.

## 7. The script body is sent once

`redis.NewScript` + `Script.Run` means EVALSHA first, EVAL only on
`NOSCRIPT`. So the ~200-byte body crosses the wire once per Redis script
cache, not once per login. Check with `redis-cli INFO commandstats`
after a few hundred attempts: `cmdstat_evalsha` should climb while
`cmdstat_eval` stays at 1. A `SCRIPT FLUSH` mid-traffic must not cause
errors — the next call reloads and retries.

## Postgres

Nothing to run. This feature adds **no table, no column and no
migration** — the counters live in Redis and nowhere else.

## Known limits

- **Fixed window, not sliding.** A client can spend its whole budget at
  the end of one window and again at the start of the next, so a burst
  of up to 2×limit is reachable across a window boundary. This matches
  the in-memory limiter exactly, which is the point: the two are
  interchangeable, and a sliding window would be a different feature
  with a different cost.
- **One round trip per attempt.** Every `SignUp`/`Login`/
  `RequestMagicLink` now waits on Redis. Keep it close to the app; a
  cross-region Redis puts its latency in front of every login.
- **Counters are not durable and should not be.** A Redis restart
  forgets every window. That is acceptable for rate limiting and is why
  no persistence is configured or required here — do not reach for
  `AOF` on this account.
- **Redis becomes a dependency of the login path.** See §6. Decide
  fail-closed versus fail-open deliberately rather than discovering the
  default during an incident.
- **The engine never closes the client.** It didn't open it. Lifecycle,
  pooling, TLS, auth and retries are all yours, configured on the
  client you pass in.
- **No per-key overrides.** One limit and one window apply to every key
  a limiter serves. Different budgets for signup and login means two
  limiters and, since the engine holds one, a small dispatching
  `RateLimiter` of your own that picks between them on the key's prefix.
