// Command cloud-loggers is a standalone, no-database smoke test for
// shipping cryden's logs to somewhere other than stdout. There is no
// DatadogLogger to test — the engine never makes the outbound call
// itself — so what is under test is everything a host needs on this side
// of that call: the request context reaching a sink that can read a trace
// ID out of it, a level filter that does not strip that context on the
// way through, redaction of the two fields the engine puts personal data
// in, fan-out to several sinks at once, one sink panicking without taking
// the login down, and the default that makes all of this optional. Run
// with:
//
//	go run ./cmd/smoketest/cloud-loggers
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/store/memory"
)

const (
	email    = "raymondproguy@dev.com"
	password = "Tr0ubl3-Fr33!2026"
	// Long enough to fail the password check for the right reason rather
	// than the policy's.
	wrongPassword = "Wr0ng-Guess!2026"

	homeIP   = "1.2.3.4"
	officeIP = "203.0.113.7"

	chromeWindows = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

	traceID      = "trace-7f3c19"
	otherTraceID = "trace-b02e55"

	// A value of its own, not the JWT secret or the encryption key.
	logHashKey = "smoketest-log-redaction-key"
)

var failures int

// traceKey is the sort of key a host app's tracing middleware uses: its
// own unexported type. That is the whole reason the engine cannot pull
// the trace ID out itself and has to hand the context over intact.
type traceKey struct{}

func traced(id string) context.Context {
	return context.WithValue(context.Background(), traceKey{}, id)
}

func traceOf(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(traceKey{}).(string)
	return id
}

// captured is one log record as a sink saw it.
type captured struct {
	level  logger.Level
	msg    string
	fields map[string]string
	trace  string
}

// collector stands in for a host's real cloud sink — the code that would
// batch these up and POST them to a vendor. It implements ContextLogger,
// so it gets the call context; bare counts records that arrived through
// the four context-free methods instead, which is how this test proves a
// wrapper did not quietly drop that context on the way.
//
// No mutex: every engine call here logs on the calling goroutine.
type collector struct {
	records []captured
	bare    int
}

func (c *collector) Log(ctx context.Context, level logger.Level, msg string, fields map[string]string) {
	c.records = append(c.records, captured{level: level, msg: msg, fields: fields, trace: traceOf(ctx)})
}

func (c *collector) Debug(msg string, fields map[string]string) {
	c.recordBare(logger.LevelDebug, msg, fields)
}

func (c *collector) Info(msg string, fields map[string]string) {
	c.recordBare(logger.LevelInfo, msg, fields)
}

func (c *collector) Warn(msg string, fields map[string]string) {
	c.recordBare(logger.LevelWarn, msg, fields)
}

func (c *collector) Error(msg string, fields map[string]string) {
	c.recordBare(logger.LevelError, msg, fields)
}

func (c *collector) recordBare(level logger.Level, msg string, fields map[string]string) {
	c.bare++
	c.records = append(c.records, captured{level: level, msg: msg, fields: fields})
}

var _ logger.ContextLogger = (*collector)(nil)

func (c *collector) countAtLevel(level logger.Level) int {
	n := 0
	for _, r := range c.records {
		if r.level == level {
			n++
		}
	}
	return n
}

// withTrace counts records that arrived carrying id — the number that
// would land in the vendor's index correlated with the rest of the
// request rather than floating on their own.
func (c *collector) withTrace(id string) int {
	n := 0
	for _, r := range c.records {
		if r.trace == id {
			n++
		}
	}
	return n
}

// mentioning counts records with value in any field, which is how the
// redaction sections ask "did the address leave the building".
func (c *collector) mentioning(value string) int {
	n := 0
	for _, r := range c.records {
		for _, v := range r.fields {
			if v == value {
				n++
				break
			}
		}
	}
	return n
}

// valuesOf returns what each record carried under key, skipping records
// that had no such field.
func (c *collector) valuesOf(key string) []string {
	var out []string
	for _, r := range c.records {
		if v, ok := r.fields[key]; ok {
			out = append(out, v)
		}
	}
	return out
}

// brokenSink is the sink whose vendor client is having a bad day.
type brokenSink struct {
	calls int
}

func (b *brokenSink) Debug(string, map[string]string) { b.explode() }
func (b *brokenSink) Info(string, map[string]string)  { b.explode() }
func (b *brokenSink) Warn(string, map[string]string)  { b.explode() }
func (b *brokenSink) Error(string, map[string]string) { b.explode() }

func (b *brokenSink) explode() {
	b.calls++
	panic("vendor client exploded")
}

var _ logger.Logger = (*brokenSink)(nil)

func newEngine(log logger.Logger) (*cryden.Engine, error) {
	return cryden.New(cryden.Config{
		JWTSecret: "smoketest-jwt-secret",
		Users:     memory.NewUserStore(),
		Sessions:  memory.NewSessionStore(),
		Audit:     memory.NewAuditStore(),
		// Repeated logins from one address are this test's normal shape,
		// not an attack on it.
		RateLimitAttempts: 1000,
		Logger:            log,
	})
}

// realTraffic drives one engine through the calls whose records the
// sections below read: a signup and a good login, which log Info records
// carrying user_id, and a bad one, which logs a Warn record carrying ip.
func realTraffic(ctx context.Context, engine *cryden.Engine, ip string) error {
	if _, err := cryden.SignUp(ctx, engine, email, password, ip); err != nil {
		return err
	}
	if _, err := cryden.Login(ctx, engine, email, password, ip, chromeWindows); err != nil {
		return err
	}
	if _, err := cryden.Login(ctx, engine, email, wrongPassword, ip, chromeWindows); err == nil {
		return fmt.Errorf("a login with the wrong password was accepted")
	}
	return nil
}

func main() {
	contextReachesACloudSink()
	aContextFreeSinkStillGetsEverything()
	filteringDropsChatterNotTheTrace()
	maskingKeepsAddressesIn()
	hashingKeepsThemCorrelatable()
	fanOutKeepsTheLocalCopyWhole()
	aPanickingSinkNeverBreaksALogin()
	theDefaultWritesJSONToStdout()

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
		return
	}
	fmt.Printf("%d CHECK(S) FAILED\n", failures)
	os.Exit(1)
}

// The point of the whole item: a record arriving at a hosted sink is only
// worth having if it can be tied back to the request that caused it, and
// the trace ID lives under a key only the host app knows.
func contextReachesACloudSink() {
	section("a sink that reads the context gets the caller's trace ID")

	sink := &collector{}
	engine, err := newEngine(sink)
	check("engine wired with a ContextLogger sink", err)
	if engine == nil {
		return
	}

	ctx := traced(traceID)
	check("signup and two logins", realTraffic(ctx, engine, homeIP))

	expectCount("every record carried the trace ID", sink.withTrace(traceID), len(sink.records))
	expectCount("none arrived through a context-free method", sink.bare, 0)
	if len(sink.records) == 0 {
		fail("the engine logged nothing at all, so nothing above proved anything")
		return
	}
	pass(fmt.Sprintf("%d records reached the sink", len(sink.records)))

	// A second request must not inherit the first one's ID: the binding
	// lives and dies inside one facade call.
	before := len(sink.records)
	_, err = cryden.Login(traced(otherTraceID), engine, email, password, homeIP, chromeWindows)
	check("a second login on its own trace", err)
	expectCount("the new records carry the new trace only", sink.withTrace(otherTraceID), len(sink.records)-before)
	expectCount("the first trace gained nothing", sink.withTrace(traceID), before)
}

// The negative of the above, and the reason ContextLogger is a second
// interface rather than a change to Logger: every host Logger written
// before any of this existed still receives every record.
func aContextFreeSinkStillGetsEverything() {
	section("a plain Logger, with no Log method at all, still works")

	sink := &plainSink{}
	engine, err := newEngine(sink)
	check("engine wired with a context-free sink", err)
	if engine == nil {
		return
	}

	check("signup and two logins", realTraffic(traced(traceID), engine, homeIP))

	if sink.calls == 0 {
		fail("a context-free sink received nothing")
		return
	}
	pass(fmt.Sprintf("%d records reached the plain sink", sink.calls))
}

// A host paying per ingested log line wants the debug chatter gone. The
// trap is that a filter forwarding through Debug/Info/Warn/Error would
// drop the context while it was at it, making "cheap" and "correlated" a
// choice nobody should have to make.
func filteringDropsChatterNotTheTrace() {
	section("a level filter drops the chatter and keeps the trace")

	unfiltered := &collector{}
	loud, err := newEngine(unfiltered)
	check("engine wired without a filter", err)
	sink := &collector{}
	quiet, err := newEngine(logger.NewLevelFilter(sink, logger.LevelWarn))
	check("engine wired at warn and above", err)
	if loud == nil || quiet == nil {
		return
	}

	check("identical traffic through the loud engine", realTraffic(traced(traceID), loud, homeIP))
	check("identical traffic through the quiet engine", realTraffic(traced(traceID), quiet, homeIP))

	if unfiltered.countAtLevel(logger.LevelInfo) == 0 {
		fail("the unfiltered engine logged nothing at info, so there was nothing for the filter to drop")
		return
	}
	pass(fmt.Sprintf("unfiltered: %d info record(s) the filter should swallow", unfiltered.countAtLevel(logger.LevelInfo)))

	expectCount("nothing below warn got through", sink.countAtLevel(logger.LevelInfo)+sink.countAtLevel(logger.LevelDebug), 0)
	if sink.countAtLevel(logger.LevelWarn)+sink.countAtLevel(logger.LevelError) == 0 {
		fail("the filter swallowed the failed login too")
		return
	}
	pass(fmt.Sprintf("%d warn/error record(s) survived", sink.countAtLevel(logger.LevelWarn)+sink.countAtLevel(logger.LevelError)))
	expectCount("the survivors kept their trace ID", sink.withTrace(traceID), len(sink.records))
	expectCount("none arrived through a context-free method", sink.bare, 0)
}

// Shipping logs out is where PII stops being an internal matter: these
// records now sit in a third party's index under its retention policy.
func maskingKeepsAddressesIn() {
	section("masking replaces the values that identify a person")

	sink := &collector{}
	engine, err := newEngine(logger.NewMaskingRedactor(sink))
	check("engine wired with a masking redactor", err)
	if engine == nil {
		return
	}

	check("signup and two logins", realTraffic(traced(traceID), engine, homeIP))

	expectCount("no record mentions the address", sink.mentioning(homeIP), 0)
	expectAllRedacted("every ip field", sink.valuesOf("ip"))
	expectAllRedacted("every user_id field", sink.valuesOf("user_id"))

	// Surgical, not a blanket: the reason a login failed is what an
	// operator is reading the record for.
	reasons := sink.valuesOf("reason")
	if len(reasons) == 0 {
		fail("no record carried a reason field, so nothing proved redaction is scoped")
		return
	}
	for _, value := range reasons {
		if value == logger.RedactedMarker {
			fail("the failure reason was redacted along with the address")
			return
		}
	}
	pass(fmt.Sprintf("%d unlisted field(s) came through untouched: %v", len(reasons), reasons))
}

// The mode that exists because "one address, forty accounts" is the shape
// credential stuffing has, and a fixed marker erases it.
func hashingKeepsThemCorrelatable() {
	section("hashing keeps one address readable as one address")

	sink := &collector{}
	redactor, err := logger.NewHashingRedactor(sink, logHashKey)
	check("hashing redactor built", err)
	if redactor == nil {
		return
	}
	engine, err := newEngine(redactor)
	check("engine wired with it", err)
	if engine == nil {
		return
	}

	ctx := traced(traceID)
	_, err = cryden.SignUp(ctx, engine, email, password, homeIP)
	check("signup", err)
	for _, ip := range []string{homeIP, homeIP, officeIP} {
		if _, err := cryden.Login(ctx, engine, email, wrongPassword, ip, chromeWindows); err == nil {
			fail("a login with the wrong password was accepted")
			return
		}
	}
	pass("three failed logins, two of them from the same address")

	expectCount("neither address appears in any record", sink.mentioning(homeIP)+sink.mentioning(officeIP), 0)

	digests := sink.valuesOf("ip")
	if len(digests) < 3 {
		fail(fmt.Sprintf("expected at least 3 ip fields to compare, got %d", len(digests)))
		return
	}
	distinct := make(map[string]struct{}, len(digests))
	for _, digest := range digests {
		if !strings.HasPrefix(digest, "hmac-sha256:") {
			fail(fmt.Sprintf("a digest should say what it is, got %q", digest))
			return
		}
		distinct[digest] = struct{}{}
	}
	expectCount("three attempts from two addresses became two digests", len(distinct), 2)

	// Negative: a redactor hashing with an empty key would produce output
	// that looks correlatable while being a lookup table away from the
	// address itself, so it is refused outright.
	empty, err := logger.NewHashingRedactor(sink, "")
	if !errors.Is(err, logger.ErrMissingHashKey) {
		fail(fmt.Sprintf("an empty hash key returned %v, want ErrMissingHashKey", err))
		return
	}
	if empty != nil {
		fail("a redactor that cannot hash was returned anyway")
		return
	}
	pass("an empty hash key is refused (ErrMissingHashKey)")
}

// The wiring the package recommends: redact inside the fan-out, so the
// local copy stays complete and only the outbound one is reduced.
func fanOutKeepsTheLocalCopyWhole() {
	section("fan-out: the local sink keeps the address, the outbound one never sees it")

	local, cloud := &collector{}, &collector{}
	engine, err := newEngine(logger.NewMultiLogger(local, logger.NewMaskingRedactor(cloud)))
	check("engine wired with two sinks, one of them redacted", err)
	if engine == nil {
		return
	}

	check("signup and two logins", realTraffic(traced(traceID), engine, homeIP))

	if len(local.records) == 0 {
		fail("the fan-out delivered nothing")
		return
	}
	expectCount("both sinks got every record", len(cloud.records), len(local.records))
	if local.mentioning(homeIP) == 0 {
		fail("the local sink lost the real address, so redaction is not scoped to one sink")
	} else {
		pass(fmt.Sprintf("the local sink kept the address on %d record(s)", local.mentioning(homeIP)))
	}
	expectCount("the outbound sink never saw it", cloud.mentioning(homeIP), 0)
	expectCount("both kept the trace ID", local.withTrace(traceID)+cloud.withTrace(traceID), len(local.records)+len(cloud.records))
}

// A log statement is never the point of the call it sits inside.
func aPanickingSinkNeverBreaksALogin() {
	section("one sink panicking does not take the login with it")

	broken, sink := &brokenSink{}, &collector{}
	engine, err := newEngine(logger.NewMultiLogger(broken, sink))
	check("engine wired with a broken sink ahead of a good one", err)
	if engine == nil {
		return
	}

	read, restore := capture(&os.Stderr)
	trafficErr := realTraffic(traced(traceID), engine, homeIP)
	restore()
	notices := read()

	check("signup and two logins despite the broken sink", trafficErr)
	if broken.calls == 0 {
		fail("the broken sink was never called, so nothing was survived")
		return
	}
	pass(fmt.Sprintf("the broken sink panicked %d time(s)", broken.calls))
	if len(sink.records) == 0 {
		fail("the sink after the broken one got nothing — a fan-out has to keep going")
		return
	}
	pass(fmt.Sprintf("the sink behind it still got %d record(s)", len(sink.records)))
	// Not swallowed: a sink failing invisibly is worse than one failing
	// loudly.
	expectCount("every lost record was reported on stderr", strings.Count(notices, "logger: a sink panicked"), broken.calls)
}

// None of the above is required. Left alone, the engine writes JSON to
// stdout, which every log shipper in existence can already tail — the
// reason this item ships no vendor client at all.
func theDefaultWritesJSONToStdout() {
	section("with no Logger configured at all, JSON still goes to stdout")

	engine, err := newEngine(nil)
	check("engine wired with no Logger", err)
	if engine == nil {
		return
	}

	read, restore := capture(&os.Stdout)
	trafficErr := realTraffic(traced(traceID), engine, homeIP)
	restore()
	out := read()

	check("signup and two logins", trafficErr)

	lines := parseLines(out)
	if len(lines) == 0 {
		fail("nothing was written to stdout")
		return
	}
	pass(fmt.Sprintf("%d JSON line(s) on stdout", len(lines)))

	stamps := make(map[string]struct{}, len(lines))
	for i, line := range lines {
		if line.Level == "" || line.Message == "" {
			fail(fmt.Sprintf("line %d is missing a level or a message: %+v", i, line))
			return
		}
		if _, err := time.Parse(time.RFC3339Nano, line.Timestamp); err != nil {
			fail(fmt.Sprintf("line %d has an unparseable timestamp %q: %v", i, line.Timestamp, err))
			return
		}
		stamps[line.Timestamp] = struct{}{}
	}
	pass("every line carries a level, a message and an RFC3339Nano timestamp")

	// The reason for nanosecond precision: at second precision one login's
	// records all share a timestamp and nothing downstream can order them.
	if len(stamps) < 2 {
		fail(fmt.Sprintf("all %d lines share one timestamp, so nothing can order them", len(lines)))
		return
	}
	pass(fmt.Sprintf("%d distinct timestamps across %d lines", len(stamps), len(lines)))

	for _, line := range lines {
		if _, ok := line.Fields["user_id"]; ok {
			pass("fields survive the round trip through JSON (user_id present)")
			return
		}
	}
	fail("no line carried a fields object")
}

// plainSink is a host Logger written before ContextLogger existed: four
// methods, no context anywhere. It must keep working untouched, which is
// why ContextLogger is a second interface and not a fifth method.
type plainSink struct {
	calls int
}

func (p *plainSink) Debug(string, map[string]string) { p.calls++ }
func (p *plainSink) Info(string, map[string]string)  { p.calls++ }
func (p *plainSink) Warn(string, map[string]string)  { p.calls++ }
func (p *plainSink) Error(string, map[string]string) { p.calls++ }

var _ logger.Logger = (*plainSink)(nil)

// consoleLine mirrors what ConsoleJSONLogger writes, decoded back.
type consoleLine struct {
	Level     string            `json:"level"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields"`
	Timestamp string            `json:"timestamp"`
}

func parseLines(out string) []consoleLine {
	var lines []consoleLine
	for _, raw := range strings.Split(strings.TrimSpace(out), "\n") {
		if raw == "" {
			continue
		}
		var line consoleLine
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			fail(fmt.Sprintf("stdout line %q is not JSON: %v", raw, err))
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

// capture swaps a standard stream for a pipe, so a section can read what
// was written to it. Call restore before read, so a failure reported
// while reading is not itself swallowed by the capture.
func capture(stream **os.File) (read func() string, restore func()) {
	r, w, err := os.Pipe()
	if err != nil {
		fail(fmt.Sprintf("creating a pipe: %v", err))
		return func() string { return "" }, func() {}
	}
	original := *stream
	*stream = w
	return func() string {
		w.Close()
		out, readErr := io.ReadAll(r)
		if readErr != nil {
			fail(fmt.Sprintf("reading the captured stream: %v", readErr))
		}
		return string(out)
	}, func() { *stream = original }
}

func section(name string) {
	fmt.Printf("\n— %s\n", name)
}

func expectAllRedacted(step string, values []string) {
	if len(values) == 0 {
		fail(step + ": no such field was ever logged, so nothing was redacted")
		return
	}
	for _, value := range values {
		if value != logger.RedactedMarker {
			fail(fmt.Sprintf("%s: got %q, want %q", step, value, logger.RedactedMarker))
			return
		}
	}
	pass(fmt.Sprintf("%s (%d of them) reads %s", step, len(values), logger.RedactedMarker))
}

func expectCount(step string, got, want int) {
	if got != want {
		fail(fmt.Sprintf("%s: got %d, want %d", step, got, want))
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
