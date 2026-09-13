package security

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// fakeRedis stands in for a Redis server: the four things
// redisFixedWindowLimit actually depends on (INCR, PTTL, PEXPIRE and
// lazy expiry of a key whose TTL has passed), plus the
// EVALSHA-NOSCRIPT-EVAL handshake go-redis performs against a server
// that has not cached the script yet.
//
// What this proves and what it cannot: it exercises every decision made
// on the Go side — key namespacing, argument order and units, the limit
// comparison, error handling, the script-cache fallback, and that two
// limiters over one server share a counter — against the semantics the
// Lua is written against. It does not run the Lua, so it cannot prove
// the script is valid Lua or that a real server's INCR/PTTL/PEXPIRE
// behave as modelled below. docs/testing/redis-rate-limiter.md covers
// that half, against a real server.
type fakeRedis struct {
	mu     sync.Mutex
	counts map[string]int64
	expiry map[string]time.Time
	// now is a frozen clock, so a window can roll over without the test
	// sleeping through it.
	now time.Time
	// cached is whether the script has been loaded, i.e. whether EVALSHA
	// works yet. A real server starts out with an empty script cache.
	cached bool
	// err, when set, fails every command — a Redis that is unreachable,
	// out of memory, or refusing writes.
	err error

	evalSha, eval int
	lastKeys      []string

	// t reports an argument the limiter should never have sent; see
	// argInt64.
	t *testing.T
}

func newFakeRedis(t *testing.T) *fakeRedis {
	return &fakeRedis{
		t:      t,
		counts: map[string]int64{},
		expiry: map[string]time.Time{},
		now:    time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC),
	}
}

func (f *fakeRedis) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// script applies redisFixedWindowLimit's logic. Kept deliberately
// line-for-line with the Lua so a change to one is obvious in review of
// the other.
func (f *fakeRedis) script(keys []string, args []any) int64 {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()

	key := keys[0]
	f.lastKeys = keys
	windowMS := f.argInt64(args[0])
	limit := f.argInt64(args[1])

	// A real server drops an expired key before any command reads it.
	if exp, ok := f.expiry[key]; ok && !f.now.Before(exp) {
		delete(f.counts, key)
		delete(f.expiry, key)
	}

	f.counts[key]++
	hits := f.counts[key]
	if hits == 1 || f.pttl(key) < 0 {
		f.expiry[key] = f.now.Add(time.Duration(windowMS) * time.Millisecond)
	}
	if hits > limit {
		return 0
	}
	return 1
}

// pttl is PTTL for a key already known to exist: milliseconds left, or
// -1 when no expiry was ever set on it.
func (f *fakeRedis) pttl(key string) int64 {
	exp, ok := f.expiry[key]
	if !ok {
		return -1
	}
	return exp.Sub(f.now).Milliseconds()
}

// argInt64 doubles as an assertion about what the limiter sends: Redis
// takes its arguments as strings and Lua's tonumber would quietly
// accept a float, so a window arriving as a time.Duration (nanoseconds)
// rather than a count of milliseconds has to fail here, loudly, instead
// of producing a window a billion times too long.
func (f *fakeRedis) argInt64(arg any) int64 {
	f.t.Helper()
	switch v := arg.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	default:
		f.t.Fatalf("script argument %#v has unexpected type %T", arg, arg)
		return 0
	}
}

func (f *fakeRedis) Eval(_ context.Context, _ string, keys []string, args ...any) *redis.Cmd {
	f.mu.Lock()
	f.eval++
	err := f.err
	if err == nil {
		// A failing EVAL never reached the script cache, so it must not
		// leave the fake claiming the body is loaded.
		f.cached = true
	}
	f.mu.Unlock()
	if err != nil {
		return redis.NewCmdResult(nil, err)
	}
	return redis.NewCmdResult(f.script(keys, args), nil)
}

func (f *fakeRedis) EvalSha(_ context.Context, _ string, keys []string, args ...any) *redis.Cmd {
	f.mu.Lock()
	f.evalSha++
	err, cached := f.err, f.cached
	f.mu.Unlock()
	if err != nil {
		return redis.NewCmdResult(nil, err)
	}
	if !cached {
		return redis.NewCmdResult(nil, redis.ErrNoScript)
	}
	return redis.NewCmdResult(f.script(keys, args), nil)
}

func (f *fakeRedis) EvalRO(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd {
	return f.Eval(ctx, script, keys, args...)
}

func (f *fakeRedis) EvalShaRO(ctx context.Context, sha1 string, keys []string, args ...any) *redis.Cmd {
	return f.EvalSha(ctx, sha1, keys, args...)
}

func (f *fakeRedis) ScriptExists(_ context.Context, _ ...string) *redis.BoolSliceCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	return redis.NewBoolSliceResult([]bool{f.cached}, f.err)
}

func (f *fakeRedis) ScriptLoad(_ context.Context, _ string) *redis.StringCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return redis.NewStringResult("", f.err)
	}
	f.cached = true
	return redis.NewStringResult("fake-sha", nil)
}

var _ redis.Scripter = (*fakeRedis)(nil)

func (f *fakeRedis) ttlOf(key string) time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	exp, ok := f.expiry[key]
	if !ok {
		return -1
	}
	return exp.Sub(f.now)
}

// seed plants a counter with no expiry on it, the state the script's
// PTTL branch exists to recover from.
func (f *fakeRedis) seed(key string, hits int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts[key] = hits
}

func (f *fakeRedis) lastKey() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.lastKeys) == 0 {
		return ""
	}
	return f.lastKeys[0]
}

func mustLimiter(t *testing.T, client redis.Scripter, limit int, window time.Duration) *RedisRateLimiter {
	t.Helper()
	rl, err := NewRedisRateLimiter(client, limit, window)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}
	return rl
}

func allow(t *testing.T, rl *RedisRateLimiter, key string) bool {
	t.Helper()
	allowed, err := rl.Allow(context.Background(), key)
	if err != nil {
		t.Fatalf("unexpected error from Allow(%q): %v", key, err)
	}
	return allowed
}

func TestNewRedisRateLimiter_RejectsANilClient(t *testing.T) {
	if _, err := NewRedisRateLimiter(nil, 10, time.Minute); err != ErrNilRedisClient {
		t.Errorf("expected ErrNilRedisClient, got %v", err)
	}
}

func TestNewRedisRateLimiter_RejectsANonPositiveLimit(t *testing.T) {
	for _, limit := range []int{0, -1} {
		if _, err := NewRedisRateLimiter(newFakeRedis(t), limit, time.Minute); err != ErrInvalidRateLimit {
			t.Errorf("limit %d: expected ErrInvalidRateLimit, got %v", limit, err)
		}
	}
}

// A window under a millisecond has no honest representation in PEXPIRE,
// so it is rejected rather than rounded to zero (which Redis refuses) or
// to one (which would silently not be what was asked for).
func TestNewRedisRateLimiter_RejectsAWindowUnderOneMillisecond(t *testing.T) {
	for _, window := range []time.Duration{0, 500 * time.Microsecond} {
		if _, err := NewRedisRateLimiter(newFakeRedis(t), 10, window); err != ErrInvalidRateWindow {
			t.Errorf("window %v: expected ErrInvalidRateWindow, got %v", window, err)
		}
	}
	if _, err := NewRedisRateLimiter(newFakeRedis(t), 10, time.Millisecond); err != nil {
		t.Errorf("a one-millisecond window is the smallest valid one, got %v", err)
	}
}

// The same expectation TestInMemoryRateLimiter_AllowsUpToLimit sets for
// the in-process limiter, asserted here so the two stay interchangeable.
func TestRedisRateLimiter_AllowsUpToTheLimitThenDenies(t *testing.T) {
	rl := mustLimiter(t, newFakeRedis(t), 3, time.Minute)

	for i := 0; i < 3; i++ {
		if !allow(t, rl, "key1") {
			t.Fatalf("expected call %d to be allowed", i+1)
		}
	}
	if allow(t, rl, "key1") {
		t.Error("expected the 4th call within the window to be denied")
	}
}

func TestRedisRateLimiter_KeysAreIndependent(t *testing.T) {
	rl := mustLimiter(t, newFakeRedis(t), 1, time.Minute)

	if !allow(t, rl, "a") || !allow(t, rl, "b") {
		t.Fatal("expected the first call for each independent key to be allowed")
	}
	if allow(t, rl, "a") {
		t.Error("expected the second call for key 'a' to be denied")
	}
}

func TestRedisRateLimiter_ResetsAfterTheWindow(t *testing.T) {
	server := newFakeRedis(t)
	rl := mustLimiter(t, server, 1, time.Minute)

	if !allow(t, rl, "key1") {
		t.Fatal("expected the first call to be allowed")
	}
	if allow(t, rl, "key1") {
		t.Fatal("expected the second call inside the window to be denied")
	}

	server.advance(time.Minute + time.Second)

	if !allow(t, rl, "key1") {
		t.Error("expected a call after the window expired to be allowed again")
	}
}

// Fixed window, not sliding: the expiry is armed by the call that
// created the counter and never pushed out, so hammering a key while
// denied cannot postpone its own reset. Worth pinning down because the
// obvious Redis idiom — PEXPIRE on every call — would quietly turn a
// blocked attacker's own traffic into a permanent block.
func TestRedisRateLimiter_DenialDoesNotExtendTheWindow(t *testing.T) {
	server := newFakeRedis(t)
	rl := mustLimiter(t, server, 1, time.Minute)

	allow(t, rl, "key1")
	server.advance(30 * time.Second)
	for i := 0; i < 5; i++ {
		if allow(t, rl, "key1") {
			t.Fatalf("expected denial %d inside the window", i+1)
		}
	}

	server.advance(31 * time.Second)

	if !allow(t, rl, "key1") {
		t.Error("expected the window to still expire on its original schedule")
	}
}

// The caller's key is opaque and arbitrary ("login:1.2.3.4:someone@
// example.com"); the prefix is what keeps it from landing on top of
// something the host app keeps in the same Redis.
func TestRedisRateLimiter_NamespacesKeys(t *testing.T) {
	server := newFakeRedis(t)
	rl := mustLimiter(t, server, 5, time.Minute)
	allow(t, rl, "login:1.2.3.4:raymondproguy@dev.com")
	if got, want := server.lastKey(), DefaultRedisKeyPrefix+"login:1.2.3.4:raymondproguy@dev.com"; got != want {
		t.Errorf("default prefix: server saw key %q, want %q", got, want)
	}

	custom, err := NewRedisRateLimiterWithPrefix(server, 5, time.Minute, "staging:rl:")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	allow(t, custom, "signup:1.2.3.4")
	if got, want := server.lastKey(), "staging:rl:signup:1.2.3.4"; got != want {
		t.Errorf("custom prefix: server saw key %q, want %q", got, want)
	}

	bare, err := NewRedisRateLimiterWithPrefix(server, 5, time.Minute, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	allow(t, bare, "signup:1.2.3.4")
	if got, want := server.lastKey(), "signup:1.2.3.4"; got != want {
		t.Errorf("empty prefix: server saw key %q, want %q", got, want)
	}
}

// Two prefixes over one server are two separate windows — the point of
// NewRedisRateLimiterWithPrefix.
func TestRedisRateLimiter_PrefixesDoNotShareCounters(t *testing.T) {
	server := newFakeRedis(t)
	staging, err := NewRedisRateLimiterWithPrefix(server, 1, time.Minute, "staging:")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	prod, err := NewRedisRateLimiterWithPrefix(server, 1, time.Minute, "prod:")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !allow(t, staging, "login:same-key") {
		t.Fatal("expected staging's first call to be allowed")
	}
	if !allow(t, prod, "login:same-key") {
		t.Error("expected production's first call to be unaffected by staging's")
	}
}

// The reason this implementation exists: N replicas, one window. Two
// limiters over one server is what that looks like from inside a test.
func TestRedisRateLimiter_TwoLimitersShareOneWindow(t *testing.T) {
	server := newFakeRedis(t)
	replicaA := mustLimiter(t, server, 2, time.Minute)
	replicaB := mustLimiter(t, server, 2, time.Minute)

	if !allow(t, replicaA, "login:1.2.3.4") {
		t.Fatal("expected replica A's first call to be allowed")
	}
	if !allow(t, replicaB, "login:1.2.3.4") {
		t.Fatal("expected replica B's call to be allowed as the window's second")
	}
	if allow(t, replicaA, "login:1.2.3.4") {
		t.Error("expected the third call to be denied: the limit is shared, not per replica")
	}
}

// PEXPIRE takes milliseconds, and the argument reaching it has to be a
// count of them — a time.Duration would arrive as nanoseconds and set a
// window a million times too long.
func TestRedisRateLimiter_SendsTheWindowInMilliseconds(t *testing.T) {
	server := newFakeRedis(t)
	rl := mustLimiter(t, server, 5, 2*time.Second)

	allow(t, rl, "k")

	if got := server.ttlOf(DefaultRedisKeyPrefix + "k"); got != 2*time.Second {
		t.Errorf("counter TTL is %v, want %v", got, 2*time.Second)
	}
}

// A counter with no TTL — set by hand, or left behind by a process that
// died between an INCR and a PEXPIRE — would otherwise count up forever
// and lock its key out permanently. The script re-arms the window
// instead, so the counter recovers on its own one window later.
func TestRedisRateLimiter_RearmsACounterThatHasNoExpiry(t *testing.T) {
	server := newFakeRedis(t)
	rl := mustLimiter(t, server, 5, time.Minute)
	key := DefaultRedisKeyPrefix + "login:stuck"
	server.seed(key, 99)

	if allow(t, rl, "login:stuck") {
		t.Fatal("expected a counter already past the limit to deny")
	}
	if got := server.ttlOf(key); got != time.Minute {
		t.Fatalf("expected the call to arm a %v window, got TTL %v", time.Minute, got)
	}

	server.advance(time.Minute + time.Second)

	if !allow(t, rl, "login:stuck") {
		t.Error("expected the counter to have expired and the key to recover")
	}
}

// Redis being down must not read as "allowed". The engine's callers
// (SignUp, Login, RequestMagicLink) propagate this error rather than
// deciding for the host, so a limiter that returned true here would take
// the rate limit off entirely for as long as the outage lasted.
func TestRedisRateLimiter_DeniesAndReportsWhenRedisFails(t *testing.T) {
	server := newFakeRedis(t)
	down := errors.New("dial tcp 127.0.0.1:6379: connect: connection refused")
	server.err = down
	rl := mustLimiter(t, server, 10, time.Minute)

	allowed, err := rl.Allow(context.Background(), "login:1.2.3.4")
	if allowed {
		t.Error("expected a Redis failure to deny, not to allow")
	}
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, down) {
		t.Errorf("expected the underlying error to stay unwrappable, got %v", err)
	}
}

// go-redis sends EVALSHA first and only falls back to a full EVAL when
// the server reports NOSCRIPT, which is what a cold script cache looks
// like. Asserted because it is the difference between shipping the
// script body on every single login and shipping it once.
func TestRedisRateLimiter_FallsBackToEvalUntilTheScriptIsCached(t *testing.T) {
	server := newFakeRedis(t)
	rl := mustLimiter(t, server, 10, time.Minute)

	allow(t, rl, "k")
	if server.evalSha != 1 || server.eval != 1 {
		t.Fatalf("first call: got %d EVALSHA and %d EVAL, want 1 and 1", server.evalSha, server.eval)
	}

	allow(t, rl, "k")
	if server.evalSha != 2 || server.eval != 1 {
		t.Errorf("second call: got %d EVALSHA and %d EVAL, want 2 and 1 — the script should be cached now", server.evalSha, server.eval)
	}
}
