package logger

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
)

func TestMultiLoggerWritesToEverySink(t *testing.T) {
	a, b, c := &plainLogger{}, &plainLogger{}, &plainLogger{}
	multi := NewMultiLogger(a, b, c)

	multi.Info("signup: completed", map[string]string{"user_id": "u1"})
	multi.Error("signup: audit record failed", nil)

	for i, sink := range []*plainLogger{a, b, c} {
		if len(sink.records) != 2 {
			t.Errorf("sink %d got %d records, want 2", i, len(sink.records))
			continue
		}
		if sink.records[0].level != LevelInfo || sink.records[1].level != LevelError {
			t.Errorf("sink %d got the wrong levels: %v", i, sink.records)
		}
		if sink.records[0].fields["user_id"] != "u1" {
			t.Errorf("sink %d lost the fields: %v", i, sink.records[0].fields)
		}
	}
}

func TestMultiLoggerRoutesEveryLevel(t *testing.T) {
	sink := &plainLogger{}
	multi := NewMultiLogger(sink, &plainLogger{})

	multi.Debug("d", nil)
	multi.Info("i", nil)
	multi.Warn("w", nil)
	multi.Error("e", nil)

	want := []Level{LevelDebug, LevelInfo, LevelWarn, LevelError}
	if len(sink.records) != len(want) {
		t.Fatalf("got %d records, want %d", len(sink.records), len(want))
	}
	for i, level := range want {
		if sink.records[i].level != level {
			t.Errorf("record %d arrived as %v, want %v", i, sink.records[i].level, level)
		}
	}
}

func TestMultiLoggerSkipsNilSinks(t *testing.T) {
	// The shape a host ends up with: a vendor sink configured only in
	// production, passed through without a branch at the call site.
	sink := &plainLogger{}
	multi := NewMultiLogger(sink, nil, nil)

	multi.Warn("still delivered", nil)

	if len(sink.records) != 1 {
		t.Errorf("got %d records, want 1", len(sink.records))
	}
}

func TestMultiLoggerCollapsesToTheOnlySink(t *testing.T) {
	sink := &plainLogger{}
	if got := NewMultiLogger(sink); got != Logger(sink) {
		t.Errorf("a single sink was wrapped; want it returned as-is")
	}
	if got := NewMultiLogger(nil, sink, nil); got != Logger(sink) {
		t.Errorf("a single surviving sink was wrapped; want it returned as-is")
	}
}

func TestMultiLoggerWithNothingToWriteToIsANop(t *testing.T) {
	got := NewMultiLogger()
	if _, ok := got.(*NopLogger); !ok {
		t.Fatalf("got %T, want *NopLogger", got)
	}
	got.Error("nowhere to go", nil)

	allNil := NewMultiLogger(nil, nil)
	if _, ok := allNil.(*NopLogger); !ok {
		t.Errorf("got %T from all-nil sinks, want *NopLogger", allNil)
	}
}

// A mixed fan-out is the realistic one: the console default cannot use a
// context, the vendor sink lives on it.
func TestMultiLoggerKeepsTheContextForSinksThatWantIt(t *testing.T) {
	cloud := &ctxLogger{}
	local := &plainLogger{}
	multi := NewMultiLogger(local, cloud)

	ForContext(traceContext("trace-77"), multi).Warn("login: failed attempt", map[string]string{"ip": "1.2.3.4"})

	if len(local.records) != 1 || local.records[0].level != LevelWarn {
		t.Errorf("the context-free sink did not get its record: %v", local.records)
	}
	if len(cloud.records) != 1 {
		t.Fatalf("the cloud sink got %d records, want 1", len(cloud.records))
	}
	if cloud.bare != 0 {
		t.Errorf("the cloud sink was called through a context-free method")
	}
	if got := traceOf(cloud.last().ctx); got != "trace-77" {
		t.Errorf("cloud sink saw trace %q, want %q", got, "trace-77")
	}
}

// panickingLogger is the failure mode a hosted sink actually has: a
// client that dies inside a flush, on a code path the host never tested.
type panickingLogger struct{ calls int }

func (p *panickingLogger) Debug(string, map[string]string) { p.boom() }
func (p *panickingLogger) Info(string, map[string]string)  { p.boom() }
func (p *panickingLogger) Warn(string, map[string]string)  { p.boom() }
func (p *panickingLogger) Error(string, map[string]string) { p.boom() }

func (p *panickingLogger) boom() {
	p.calls++
	panic("vendor client exploded")
}

func TestMultiLoggerIsolatesAPanickingSink(t *testing.T) {
	stderr, restore := captureStderr(t)
	defer restore()

	broken := &panickingLogger{}
	first, last := &plainLogger{}, &plainLogger{}
	multi := NewMultiLogger(first, broken, last)

	multi.Warn("login: rate limited", map[string]string{"ip": "1.2.3.4"})

	if broken.calls != 1 {
		t.Fatalf("the broken sink was called %d times, want 1", broken.calls)
	}
	if len(first.records) != 1 {
		t.Errorf("the sink before the broken one lost its record")
	}
	if len(last.records) != 1 {
		t.Errorf("the sink after the broken one never got its record — a fan-out has to keep going")
	}

	// Not swallowed: a sink failing invisibly is worse than one failing
	// loudly.
	out := stderr()
	if !strings.Contains(out, "vendor client exploded") {
		t.Errorf("stderr did not carry the panic: %q", out)
	}
	if !strings.Contains(out, "login: rate limited") {
		t.Errorf("stderr did not say which record was lost: %q", out)
	}
	if !strings.Contains(out, "warn") {
		t.Errorf("stderr did not say at what level: %q", out)
	}
}

func TestMultiLoggerClampsOutOfRangeLevels(t *testing.T) {
	sink := &plainLogger{}
	multi := NewMultiLogger(sink, &plainLogger{}).(ContextLogger)

	multi.Log(context.Background(), Level(99), "overflow", nil)
	multi.Log(nil, Level(-1), "underflow and no context", nil) //lint:ignore SA1012 under test

	if len(sink.records) != 2 {
		t.Fatalf("got %d records, want 2", len(sink.records))
	}
	if sink.records[0].level != LevelError || sink.records[1].level != LevelDebug {
		t.Errorf("clamping went wrong: %v", sink.records)
	}
}

// captureStderr swaps os.Stderr for a pipe. The returned function reads
// what was written; restore puts the real stderr back.
func captureStderr(t *testing.T) (read func() string, restore func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating a pipe: %v", err)
	}
	original := os.Stderr
	os.Stderr = w
	return func() string {
		w.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("reading captured stderr: %v", err)
		}
		return string(out)
	}, func() { os.Stderr = original }
}
