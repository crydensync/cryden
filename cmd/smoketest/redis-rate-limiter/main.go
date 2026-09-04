// Command redis-rate-limiter is a standalone smoke test for the
// Redis-backed rate limiter: the limit itself, that a window is fixed
// rather than pushed out by the traffic it is denying, that keys are
// namespaced so they cannot land on the host app's own data, that two
// engine instances pointed at one Redis share a window (the entire
// reason this implementation exists), that a counter left without an
// expiry heals instead of locking its key out forever, and what happens
// to a login when Redis is unreachable.
//
// Run with:
//
//	go run ./cmd/smoketest/redis-rate-limiter
//
// That needs no server: it runs against an in-process stand-in that
// implements the INCR/PTTL/PEXPIRE semantics the limiter's Lua is
// written against. The stand-in cannot prove the Lua is valid Lua, so
// when a real server is at hand, point this at it — the same checks
// then run against the actual script, and the ones that need to freeze
// time or break the connection announce themselves as skipped:
//
//	REDIS_ADDR=127.0.0.1:6379 go run ./cmd/smoketest/redis-rate-limiter
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/auth"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/redis/go-redis/v9"
)

const (
	email    = "raymondproguy@dev.com"
	password = "Tr0ubl3-Fr33!2026"

	callerIP = "1.2.3.4"
)

var failures int

// server is the Redis a scenario runs against: the Scripter the limiter
// needs, plus the few things only a test asks of a server — reading a
// counter's TTL, planting a counter that has none, moving past a window,
// and (stand-in only) breaking every command or counting round trips.
type server interface {
	redis.Scripter

	// exists reports whether a key is present, which is how the key a
	// limiter built is checked from outside it.
	exists(ctx context.Context, key string) (bool, error)
	// ttl is the counter's remaining window, negative when it has none.
	ttl(ctx context.Context, key string) (time.Duration, error)
	// seedWithoutTTL plants a counter with no expiry — the state the
	// script's PTTL branch exists to recover from.
	seedWithoutTTL(ctx context.Context, key string, hits int64) error
	// waitOut moves past a window of d: instantly for the stand-in,
	// by actually waiting for a real server.
	waitOut(d time.Duration)
	// breakable reports whether this server can be made to fail on
	// command. A real one cannot be, not from in here.
	breakable() bool
	// breakWith makes every command fail with err until cleared.
	breakWith(err error)
	// roundTrips is how many EVALSHA and EVAL calls have been made, or
	// (0, 0, false) when the server does not count them.
	roundTrips() (evalSha, eval int, counted bool)
	cleanup(ctx context.Context)
}

// standIn is Redis as far as this limiter is concerned: INCR, PTTL,
// PEXPIRE, lazy expiry of a key whose window has closed, and the
// EVALSHA-NOSCRIPT-EVAL handshake go-redis performs against a server
// whose script cache is cold. Single-goroutine by construction, like the
// rest of this program, so nothing here locks.
type standIn struct {
	counts map[string]int64
	expiry map[string]time.Time
	now    time.Time
	cached bool
	err    error

	evalSha, eval int
}

func newStandIn() *standIn {
	return &standIn{
		counts: map[string]int64{},
		expiry: map[string]time.Time{},
		now:    time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC),
	}
}

// script applies security's redisFixedWindowLimit, kept line-for-line
// with the Lua it stands in for.
func (s *standIn) script(keys []string, args []any) (int64, error) {
	key := keys[0]
	windowMS, err := argInt64(args[0])
	if err != nil {
		return 0, err
	}
	limit, err := argInt64(args[1])
	if err != nil {
		return 0, err
	}

	// A real server drops an expired key before any command reads it.
	if exp, ok := s.expiry[key]; ok && !s.now.Before(exp) {
		delete(s.counts, key)
		delete(s.expiry, key)
	}

	s.counts[key]++
	hits := s.counts[key]
	if hits == 1 || s.pttl(key) < 0 {
		s.expiry[key] = s.now.Add(time.Duration(windowMS) * time.Millisecond)
	}
	if hits > limit {
		return 0, nil
	}
	return 1, nil
}

// pttl is PTTL for a key already known to exist: what is left of its
// window, or -1 when no expiry was ever set on it.
func (s *standIn) pttl(key string) int64 {
	exp, ok := s.expiry[key]
	if !ok {
		return -1
	}
	return exp.Sub(s.now).Milliseconds()
}

// argInt64 is also an assertion: Redis takes arguments as strings and
// Lua's tonumber would accept a float, so a window arriving as a
// time.Duration rather than a count of milliseconds has to be rejected
// here instead of quietly becoming a window a million times too long.
func argInt64(arg any) (int64, error) {
	switch v := arg.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("script argument %#v has unexpected type %T", arg, arg)
	}
}

func (s *standIn) Eval(_ context.Context, _ string, keys []string, args ...any) *redis.Cmd {
	s.eval++
	if s.err != nil {
		// A failing EVAL never reached the script cache, so it must not
		// leave the stand-in claiming the body is loaded.
		return redis.NewCmdResult(nil, s.err)
	}
	s.cached = true
	return redis.NewCmdResult(s.script(keys, args))
}

func (s *standIn) EvalSha(_ context.Context, _ string, keys []string, args ...any) *redis.Cmd {
	s.evalSha++
	if s.err != nil {
		return redis.NewCmdResult(nil, s.err)
	}
	if !s.cached {
		return redis.NewCmdResult(nil, redis.ErrNoScript)
	}
	return redis.NewCmdResult(s.script(keys, args))
}

func (s *standIn) EvalRO(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd {
	return s.Eval(ctx, script, keys, args...)
}

func (s *standIn) EvalShaRO(ctx context.Context, sha1 string, keys []string, args ...any) *redis.Cmd {
	return s.EvalSha(ctx, sha1, keys, args...)
}

func (s *standIn) ScriptExists(_ context.Context, _ ...string) *redis.BoolSliceCmd {
	return redis.NewBoolSliceResult([]bool{s.cached}, s.err)
}

func (s *standIn) ScriptLoad(_ context.Context, _ string) *redis.StringCmd {
	if s.err != nil {
		return redis.NewStringResult("", s.err)
	}
	s.cached = true
	return redis.NewStringResult("stand-in-sha", nil)
}

func (s *standIn) exists(_ context.Context, key string) (bool, error) {
	if exp, ok := s.expiry[key]; ok && !s.now.Before(exp) {
		return false, nil
	}
	_, ok := s.counts[key]
	return ok, nil
}

func (s *standIn) ttl(_ context.Context, key string) (time.Duration, error) {
	if _, ok := s.counts[key]; !ok {
		return -2, nil
	}
	return time.Duration(s.pttl(key)) * time.Millisecond, nil
}

func (s *standIn) seedWithoutTTL(_ context.Context, key string, hits int64) error {
	s.counts[key] = hits
	delete(s.expiry, key)
	return nil
}

func (s *standIn) waitOut(d time.Duration)      { s.now = s.now.Add(d) }
func (s *standIn) breakable() bool              { return true }
func (s *standIn) breakWith(err error)          { s.err = err }
func (s *standIn) roundTrips() (int, int, bool) { return s.evalSha, s.eval, true }
func (s *standIn) cleanup(_ context.Context)    {}

var _ server = (*standIn)(nil)

// realServer is a live Redis, used when REDIS_ADDR is set: the checks
// below then run against the actual Lua instead of a model of it. Every
// key the limiter touches is recorded, so cleanup can delete exactly
// those and leave anything else on that server alone.
type realServer struct {
	client  *redis.Client
	touched map[string]bool
}

func dialRealServer(ctx context.Context, addr string) (*realServer, error) {
	client := redis.NewClient(&redis.Options{Addr: addr})
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	return &realServer{client: client, touched: map[string]bool{}}, nil
}

func (s *realServer) note(keys []string) {
	for _, k := range keys {
		s.touched[k] = true
	}
}

func (s *realServer) Eval(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd {
	s.note(keys)
	return s.client.Eval(ctx, script, keys, args...)
}

func (s *realServer) EvalSha(ctx context.Context, sha1 string, keys []string, args ...any) *redis.Cmd {
	s.note(keys)
	return s.client.EvalSha(ctx, sha1, keys, args...)
}

func (s *realServer) EvalRO(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd {
	s.note(keys)
	return s.client.EvalRO(ctx, script, keys, args...)
}

func (s *realServer) EvalShaRO(ctx context.Context, sha1 string, keys []string, args ...any) *redis.Cmd {
	s.note(keys)
	return s.client.EvalShaRO(ctx, sha1, keys, args...)
}

func (s *realServer) ScriptExists(ctx context.Context, hashes ...string) *redis.BoolSliceCmd {
	return s.client.ScriptExists(ctx, hashes...)
}

func (s *realServer) ScriptLoad(ctx context.Context, script string) *redis.StringCmd {
	return s.client.ScriptLoad(ctx, script)
}

func (s *realServer) exists(ctx context.Context, key string) (bool, error) {
	n, err := s.client.Exists(ctx, key).Result()
	return n == 1, err
}

func (s *realServer) ttl(ctx context.Context, key string) (time.Duration, error) {
	return s.client.PTTL(ctx, key).Result()
}

func (s *realServer) seedWithoutTTL(ctx context.Context, key string, hits int64) error {
	s.note([]string{key})
	return s.client.Set(ctx, key, hits, 0).Err()
}

// waitOut really waits: a live server's expiry is the server's own
// clock, and there is nothing here to fast-forward it with.
func (s *realServer) waitOut(d time.Duration) { time.Sleep(d) }

func (s *realServer) breakable() bool              { return false }
func (s *realServer) breakWith(error)              {}
func (s *realServer) roundTrips() (int, int, bool) { return 0, 0, false }

func (s *realServer) cleanup(ctx context.Context) {
	keys := make([]string, 0, len(s.touched))
	for k := range s.touched {
		keys = append(keys, k)
	}
	if len(keys) > 0 {
		if err := s.client.Del(ctx, keys...).Err(); err != nil {
			fail(fmt.Sprintf("cleaning up %d key(s): %v", len(keys), err))
		}
	}
	if err := s.client.Close(); err != nil {
		fail(fmt.Sprintf("closing the redis client: %v", err))
	}
}

var _ server = (*realServer)(nil)

// runID keeps one run's counters clear of the last one's, which matters
// against a live server where a key outlives the process that made it.
var runID = fmt.Sprintf("run-%d", time.Now().UnixNano())

// callerKey is a key of the shape auth builds — the limiter treats it as
// opaque, so the only thing that matters is that each check gets its own.
func callerKey(scenario string) string {
	return scenario + ":" + callerIP + ":" + runID
}

func mustLimiter(srv server, limit int, window time.Duration) *security.RedisRateLimiter {
	rl, err := security.NewRedisRateLimiter(srv, limit, window)
	if err != nil {
		fail(fmt.Sprintf("constructing a limiter (%d per %v): %v", limit, window, err))
		return nil
	}
	return rl
}

func mustPrefixedLimiter(srv server, limit int, window time.Duration, prefix string) *security.RedisRateLimiter {
	rl, err := security.NewRedisRateLimiterWithPrefix(srv, limit, window, prefix)
	if err != nil {
		fail(fmt.Sprintf("constructing a limiter under %q: %v", prefix, err))
		return nil
	}
	return rl
}

// engineOver is a whole engine wired to one limiter, with its own
// in-memory stores — a replica, as far as the limiter can tell. Note
// what is NOT set: RateLimitAttempts and RateLimitWindow, which a
// supplied limiter makes irrelevant.
func engineOver(limiter security.RateLimiter) (*cryden.Engine, error) {
	return cryden.New(cryden.Config{
		JWTSecret:   "smoketest-jwt-secret",
		Users:       memory.NewUserStore(),
		Sessions:    memory.NewSessionStore(),
		Audit:       memory.NewAuditStore(),
		RateLimiter: limiter,
	})
}

func main() {
	ctx := context.Background()

	srv, mode := chooseServer(ctx)
	fmt.Printf("running against %s\n", mode)

	constructorRejectsNonsense(ctx, srv)
	theLimitItself(ctx, srv)
	theWindowIsFixed(ctx, srv)
	keysAreNamespaced(ctx, srv)
	replicasShareOneWindow(ctx, srv)
	aCounterWithNoExpiryHeals(ctx, srv)
	throughTheEngine(ctx, srv)
	twoEnginesShareOneLimit(ctx, srv)
	whenRedisIsUnreachable(ctx, srv)
	theScriptIsCachedAfterFirstUse(ctx, srv)

	srv.cleanup(ctx)

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
		return
	}
	fmt.Printf("%d CHECK(S) FAILED\n", failures)
	os.Exit(1)
}

// chooseServer returns the live server at REDIS_ADDR when that is set,
// and the in-process stand-in otherwise. An unreachable REDIS_ADDR is a
// hard stop rather than a silent fall back to the stand-in: someone who
// set it wants the real script checked, and quietly not doing that is
// the one outcome worse than failing.
func chooseServer(ctx context.Context) (server, string) {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		return newStandIn(), "the in-process stand-in (set REDIS_ADDR to check the Lua against a real server)"
	}
	srv, err := dialRealServer(ctx, addr)
	if err != nil {
		fmt.Printf("✗ REDIS_ADDR=%s is set but unreachable: %v\n", addr, err)
		os.Exit(1)
	}
	return srv, "the real Redis at " + addr
}

func constructorRejectsNonsense(_ context.Context, srv server) {
	section("a limiter the host builds itself validates its own arguments")

	_, err := security.NewRedisRateLimiter(nil, 10, time.Minute)
	expectSentinel("no client at all is rejected", err, security.ErrNilRedisClient)

	for _, limit := range []int{0, -1} {
		_, err := security.NewRedisRateLimiter(srv, limit, time.Minute)
		expectSentinel(fmt.Sprintf("a limit of %d is rejected", limit), err, security.ErrInvalidRateLimit)
	}

	for _, window := range []time.Duration{0, 500 * time.Microsecond} {
		_, err := security.NewRedisRateLimiter(srv, 10, window)
		expectSentinel(fmt.Sprintf("a %v window is rejected: PEXPIRE cannot express it", window), err, security.ErrInvalidRateWindow)
	}

	if _, err := security.NewRedisRateLimiter(srv, 10, time.Millisecond); err != nil {
		fail(fmt.Sprintf("one millisecond is the smallest window PEXPIRE can express, so it should be accepted: %v", err))
	} else {
		pass("one millisecond, the smallest window PEXPIRE can express, is accepted")
	}
}

func theLimitItself(ctx context.Context, srv server) {
	section("the limit itself, and one key's traffic not touching another's")

	rl := mustLimiter(srv, 3, time.Minute)
	key := callerKey("login")

	for i := 1; i <= 3; i++ {
		expectAllow(ctx, fmt.Sprintf("call %d of 3 is allowed", i), rl, key, true)
	}
	expectAllow(ctx, "the 4th call in the same window is denied", rl, key, false)
	expectAllow(ctx, "and so is the 5th — denial is not a one-off", rl, key, false)
	expectAllow(ctx, "a different key is untouched by any of that", rl, callerKey("login-elsewhere"), true)
}

func theWindowIsFixed(ctx context.Context, srv server) {
	section("the window is fixed, not pushed out by the traffic it is denying")

	const window = 400 * time.Millisecond
	rl := mustLimiter(srv, 1, window)
	key := callerKey("magic-link")
	counter := security.DefaultRedisKeyPrefix + key

	expectAllow(ctx, "the first call is allowed", rl, key, true)
	expectWindowArmed(ctx, "and arms a window on the counter it created", srv, counter, window)
	for i := 2; i <= 5; i++ {
		expectAllow(ctx, fmt.Sprintf("call %d inside that window is denied", i), rl, key, false)
	}

	srv.waitOut(window + 100*time.Millisecond)

	expectAllow(ctx, "and the window expired on its original schedule regardless", rl, key, true)
}

func keysAreNamespaced(ctx context.Context, srv server) {
	section("keys are namespaced, so a counter cannot land on the host app's own data")

	rl := mustLimiter(srv, 5, time.Minute)
	key := callerKey("signup")
	expectAllow(ctx, "a call under the default prefix is allowed", rl, key, true)
	expectKey(ctx, "its counter is at cryden:ratelimit:<key>", srv, security.DefaultRedisKeyPrefix+key, true)
	expectKey(ctx, "and nothing at all was written at the bare key", srv, key, false)

	bare := mustPrefixedLimiter(srv, 5, time.Minute, "")
	bareKey := callerKey("signup-unprefixed")
	expectAllow(ctx, "an empty prefix is accepted and means exactly that", bare, bareKey, true)
	expectKey(ctx, "the counter is at the caller's key, verbatim", srv, bareKey, true)

	staging := mustPrefixedLimiter(srv, 1, time.Minute, "staging:"+runID+":")
	production := mustPrefixedLimiter(srv, 1, time.Minute, "production:"+runID+":")
	shared := callerKey("login-two-deployments")
	expectAllow(ctx, "staging's one call is allowed", staging, shared, true)
	expectAllow(ctx, "production's is too — a prefix is a separate window", production, shared, true)
	expectAllow(ctx, "and staging is out on its own count, not the shared one", staging, shared, false)
}

func replicasShareOneWindow(ctx context.Context, srv server) {
	section("two limiters over one Redis share a window — the reason this exists")

	replicaA := mustLimiter(srv, 2, time.Minute)
	replicaB := mustLimiter(srv, 2, time.Minute)
	key := callerKey("login-shared-window")

	expectAllow(ctx, "replica A takes the window's first call", replicaA, key, true)
	expectAllow(ctx, "replica B takes its second", replicaB, key, true)
	expectAllow(ctx, "replica A is denied the third: the limit is 2 in total, not 2 each", replicaA, key, false)
	expectAllow(ctx, "and replica B is denied too", replicaB, key, false)
}

func aCounterWithNoExpiryHeals(ctx context.Context, srv server) {
	section("a counter left without an expiry heals, instead of locking its key out forever")

	const window = 400 * time.Millisecond
	rl := mustLimiter(srv, 5, window)
	key := callerKey("login-stuck")
	counter := security.DefaultRedisKeyPrefix + key

	check("planting a counter past the limit with no TTL on it", srv.seedWithoutTTL(ctx, counter, 99))
	expectNoWindow(ctx, "the planted counter has no window to expire on", srv, counter)
	expectAllow(ctx, "the next call is denied, as a counter past its limit should be", rl, key, false)
	expectWindowArmed(ctx, "but that same call armed the window it was missing", srv, counter, window)

	srv.waitOut(window + 100*time.Millisecond)

	expectAllow(ctx, "so one window later the key is usable again", rl, key, true)
}

func throughTheEngine(ctx context.Context, srv server) {
	section("through a real engine: the limiter auth actually consults")

	limiter := mustPrefixedLimiter(srv, 1, time.Minute, "engine:"+runID+":")
	if limiter == nil {
		return
	}
	engine, err := engineOver(limiter)
	check("an engine wired with Config.RateLimiter and no attempt/window knobs", err)
	if engine == nil {
		return
	}

	_, err = cryden.SignUp(ctx, engine, email, password, callerIP)
	check("the first signup from this address goes through", err)

	_, err = cryden.SignUp(ctx, engine, "someone-else@dev.com", password, callerIP)
	expectSentinel("the second is rate limited before it reaches the store at all", err, auth.ErrRateLimited)

	_, err = cryden.Login(ctx, engine, email, password, callerIP, "curl/8.6.0")
	check("logging in still works: signup and login are counted separately", err)

	_, err = cryden.Login(ctx, engine, email, password, callerIP, "curl/8.6.0")
	expectSentinel("a second login for the same account from the same address is limited", err, auth.ErrRateLimited)
}

func twoEnginesShareOneLimit(ctx context.Context, srv server) {
	section("two engines, separate stores, one shared limit")

	prefix := "replicas:" + runID + ":"
	replicaA, errA := engineOver(mustPrefixedLimiter(srv, 1, time.Minute, prefix))
	replicaB, errB := engineOver(mustPrefixedLimiter(srv, 1, time.Minute, prefix))
	check("wiring replica A", errA)
	check("wiring replica B", errB)
	if replicaA == nil || replicaB == nil {
		return
	}

	_, err := cryden.SignUp(ctx, replicaA, email, password, callerIP)
	check("a signup on replica A goes through", err)

	_, err = cryden.SignUp(ctx, replicaB, email, password, callerIP)
	expectSentinel("the same address is now limited on replica B, which never saw that request", err, auth.ErrRateLimited)

	// The same shape with the default limiter, to show what is being
	// fixed rather than just asserting the fix: a limit of 1 that two
	// separate processes each apply to themselves lets 2 through.
	inProcessA, errA := engineWithInProcessLimit(1)
	inProcessB, errB := engineWithInProcessLimit(1)
	check("wiring two engines on the in-process default instead", errors.Join(errA, errB))
	if inProcessA == nil || inProcessB == nil {
		return
	}
	_, err = cryden.SignUp(ctx, inProcessA, email, password, callerIP)
	check("their first signup goes through as well", err)
	_, err = cryden.SignUp(ctx, inProcessB, email, password, callerIP)
	check("and so does the second — each keeps its own count, so a limit of 1 let 2 through", err)
}

// engineWithInProcessLimit is the default wiring: no Config.RateLimiter,
// so New builds an in-memory limiter from the tuning knobs.
func engineWithInProcessLimit(attempts int) (*cryden.Engine, error) {
	return cryden.New(cryden.Config{
		JWTSecret:         "smoketest-jwt-secret",
		Users:             memory.NewUserStore(),
		Sessions:          memory.NewSessionStore(),
		Audit:             memory.NewAuditStore(),
		RateLimitAttempts: attempts,
		RateLimitWindow:   time.Minute,
	})
}

func whenRedisIsUnreachable(ctx context.Context, srv server) {
	section("when Redis is unreachable, the engine fails closed")

	if !srv.breakable() {
		skip("a login fails closed while Redis is down",
			"a live server cannot be taken down from in here — stop it and re-run to see this")
		return
	}

	limiter := mustPrefixedLimiter(srv, 10, time.Minute, "outage:"+runID+":")
	if limiter == nil {
		return
	}
	engine, err := engineOver(limiter)
	check("an engine over a limiter that is about to lose its Redis", err)
	if engine == nil {
		return
	}

	_, err = cryden.SignUp(ctx, engine, email, password, callerIP)
	check("a signup while Redis is healthy", err)

	down := errors.New("dial tcp 127.0.0.1:6379: connect: connection refused")
	srv.breakWith(down)

	allowed, err := limiter.Allow(ctx, callerKey("login-during-outage"))
	expectBool("the limiter denies rather than waving the call through", allowed, false)
	expectWrapped("and reports the underlying failure to its caller", err, down)

	_, err = cryden.Login(ctx, engine, email, password, callerIP, "curl/8.6.0")
	expectFailedButNot("the login fails, and not as an ordinary rate limit", err, auth.ErrRateLimited)

	srv.breakWith(nil)

	_, err = cryden.Login(ctx, engine, email, password, callerIP, "curl/8.6.0")
	check("and everything recovers the moment Redis is back", err)
}

func theScriptIsCachedAfterFirstUse(ctx context.Context, srv server) {
	section("the script body is sent once, not on every login")

	if _, _, counted := srv.roundTrips(); !counted {
		skip("EVALSHA carries every call after the first",
			"only the stand-in counts commands; against a real server use MONITOR or INFO commandstats")
		return
	}

	// A server that has never seen this script, which is what a freshly
	// started Redis looks like.
	cold := newStandIn()
	rl := mustLimiter(cold, 10, time.Minute)
	if rl == nil {
		return
	}

	expectAllow(ctx, "the first call is allowed", rl, callerKey("login-cold-cache"), true)
	evalSha, eval, _ := cold.roundTrips()
	expectCounts("it took one EVALSHA, refused with NOSCRIPT, then one EVAL", evalSha, 1, eval, 1)

	expectAllow(ctx, "the second call is allowed too", rl, callerKey("login-cold-cache"), true)
	evalSha, eval, _ = cold.roundTrips()
	expectCounts("and took only an EVALSHA: the body was not sent again", evalSha, 2, eval, 1)
}

func section(name string) {
	fmt.Printf("\n— %s\n", name)
}

func expectAllow(ctx context.Context, step string, rl *security.RedisRateLimiter, key string, want bool) {
	if rl == nil {
		fail(step + ": no limiter to call")
		return
	}
	allowed, err := rl.Allow(ctx, key)
	if err != nil {
		fail(fmt.Sprintf("%s: unexpected error: %v", step, err))
		return
	}
	expectBool(step, allowed, want)
}

func expectBool(step string, got, want bool) {
	if got != want {
		fail(fmt.Sprintf("%s: got allowed=%t, want %t", step, got, want))
		return
	}
	pass(step)
}

func expectKey(ctx context.Context, step string, srv server, key string, want bool) {
	got, err := srv.exists(ctx, key)
	if err != nil {
		fail(fmt.Sprintf("%s: reading key %q: %v", step, key, err))
		return
	}
	if got != want {
		fail(fmt.Sprintf("%s: key %q exists=%t, want %t", step, key, got, want))
		return
	}
	pass(step)
}

// expectWindowArmed accepts anything from a hair under the full window
// down to half of it: a live server's PTTL counts down from the moment
// the counter was created, and this is checked a round trip or two later.
func expectWindowArmed(ctx context.Context, step string, srv server, key string, window time.Duration) {
	got, err := srv.ttl(ctx, key)
	if err != nil {
		fail(fmt.Sprintf("%s: reading the TTL of %q: %v", step, key, err))
		return
	}
	if got <= window/2 || got > window {
		fail(fmt.Sprintf("%s: TTL of %q is %v, want something just under %v", step, key, got, window))
		return
	}
	pass(step)
}

func expectNoWindow(ctx context.Context, step string, srv server, key string) {
	got, err := srv.ttl(ctx, key)
	if err != nil {
		fail(fmt.Sprintf("%s: reading the TTL of %q: %v", step, key, err))
		return
	}
	if got >= 0 {
		fail(fmt.Sprintf("%s: expected no TTL on %q, got %v", step, key, got))
		return
	}
	pass(step)
}

func expectCounts(step string, gotFirst, wantFirst, gotSecond, wantSecond int) {
	if gotFirst != wantFirst || gotSecond != wantSecond {
		fail(fmt.Sprintf("%s: got %d and %d, want %d and %d", step, gotFirst, gotSecond, wantFirst, wantSecond))
		return
	}
	pass(step)
}

func expectSentinel(step string, got, want error) {
	if !errors.Is(got, want) {
		fail(fmt.Sprintf("%s: got %v, want %v", step, got, want))
		return
	}
	pass(step)
}

func expectWrapped(step string, got, want error) {
	if got == nil {
		fail(step + ": expected an error, got none")
		return
	}
	if !errors.Is(got, want) {
		fail(fmt.Sprintf("%s: %v does not unwrap to %v", step, got, want))
		return
	}
	pass(step)
}

func expectFailedButNot(step string, got, notWant error) {
	if got == nil {
		fail(step + ": expected an error, got none")
		return
	}
	if errors.Is(got, notWant) {
		fail(fmt.Sprintf("%s: got %v, which is exactly what this must not be", step, got))
		return
	}
	pass(step)
}

func check(step string, err error) {
	if err != nil {
		fail(fmt.Sprintf("%s: unexpected error: %v", step, err))
		return
	}
	pass(step)
}

func pass(step string) {
	fmt.Println("✓", step)
}

func fail(msg string) {
	failures++
	fmt.Println("✗", msg)
}

// skip is neither a pass nor a failure: the check could not run in this
// mode at all, and saying so is more honest than a ✓ that checked
// nothing.
func skip(step, why string) {
	fmt.Printf("· %s — skipped: %s\n", step, why)
}
