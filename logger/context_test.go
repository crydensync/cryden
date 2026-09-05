package logger

import (
	"context"
	"testing"
)

// The whole point of the item: a record made through the four
// context-free methods still reaches a context-aware sink with the
// context of the call that produced it.
func TestForContextHandsTheContextToAContextLogger(t *testing.T) {
	sink := &ctxLogger{}
	bound := ForContext(traceContext("trace-abc"), sink)

	bound.Warn("login: rate limited", map[string]string{"ip": "1.2.3.4"})

	if sink.bare != 0 {
		t.Fatalf("record went through a context-free method %d time(s); the context was dropped", sink.bare)
	}
	got := sink.last()
	if traceOf(got.ctx) != "trace-abc" {
		t.Errorf("sink saw trace %q, want %q", traceOf(got.ctx), "trace-abc")
	}
	if got.level != LevelWarn {
		t.Errorf("sink saw level %v, want %v", got.level, LevelWarn)
	}
	if got.msg != "login: rate limited" {
		t.Errorf("sink saw message %q", got.msg)
	}
	if got.fields["ip"] != "1.2.3.4" {
		t.Errorf("sink saw fields %v", got.fields)
	}
}

func TestForContextRoutesEveryLevel(t *testing.T) {
	sink := &ctxLogger{}
	bound := ForContext(traceContext("t"), sink)

	bound.Debug("d", nil)
	bound.Info("i", nil)
	bound.Warn("w", nil)
	bound.Error("e", nil)

	want := []Level{LevelDebug, LevelInfo, LevelWarn, LevelError}
	if len(sink.records) != len(want) {
		t.Fatalf("got %d records, want %d", len(sink.records), len(want))
	}
	for i, level := range want {
		if sink.records[i].level != level {
			t.Errorf("record %d arrived as %v, want %v", i, sink.records[i].level, level)
		}
		if traceOf(sink.records[i].ctx) != "t" {
			t.Errorf("record %d lost the context", i)
		}
	}
}

// A Logger written before any of this existed must be handed back
// untouched — not wrapped in something that would call a method it does
// not have.
func TestForContextLeavesAPlainLoggerAlone(t *testing.T) {
	plain := &plainLogger{}

	got := ForContext(traceContext("trace-abc"), plain)

	if got != Logger(plain) {
		t.Fatalf("a plain Logger was wrapped; want the same value back")
	}
	got.Info("signup: completed", nil)
	if len(plain.records) != 1 || plain.records[0].level != LevelInfo {
		t.Errorf("record did not land on the bare Info method: %v", plain.records)
	}
}

func TestForContextWithoutAContextLeavesTheLoggerAlone(t *testing.T) {
	sink := &ctxLogger{}

	//lint:ignore SA1012 passing nil is exactly the case under test.
	got := ForContext(nil, sink)

	if got != Logger(sink) {
		t.Fatalf("a nil context still produced a wrapper; nothing useful could be bound")
	}
}

// Rebinding has to win, or a second binding would be silently swallowed
// by the first wrapper — which satisfies ContextLogger itself.
func TestForContextRebindingUsesTheNewerContext(t *testing.T) {
	sink := &ctxLogger{}

	outer := ForContext(traceContext("outer"), sink)
	inner := ForContext(traceContext("inner"), outer)
	inner.Error("boom", nil)

	if got := traceOf(sink.last().ctx); got != "inner" {
		t.Errorf("sink saw trace %q, want the rebound %q", got, "inner")
	}
}

// contextBound.Log falls back to its bound context when handed a nil
// one, so a wrapper standing in for a bare method cannot erase it.
func TestContextBoundLogFallsBackToTheBoundContext(t *testing.T) {
	sink := &ctxLogger{}
	bound := ForContext(traceContext("bound"), sink).(ContextLogger)

	bound.Log(nil, LevelInfo, "m", nil) //lint:ignore SA1012 under test

	if got := traceOf(sink.last().ctx); got != "bound" {
		t.Errorf("sink saw trace %q, want %q", got, "bound")
	}
}

func TestLogFuncSatisfiesTheWholeInterfaceFromOneFunction(t *testing.T) {
	var seen []record
	sink := LogFunc(func(ctx context.Context, level Level, msg string, fields map[string]string) {
		seen = append(seen, record{level: level, msg: msg, fields: fields, ctx: ctx})
	})

	sink.Debug("d", nil)
	sink.Info("i", nil)
	sink.Warn("w", nil)
	sink.Error("e", nil)
	sink.Log(traceContext("explicit"), LevelWarn, "direct", nil)

	if len(seen) != 5 {
		t.Fatalf("got %d records, want 5", len(seen))
	}
	for i, level := range []Level{LevelDebug, LevelInfo, LevelWarn, LevelError} {
		if seen[i].level != level {
			t.Errorf("record %d arrived as %v, want %v", i, seen[i].level, level)
		}
		// The bare methods have no call in scope; they must still pass a
		// usable context rather than nil, since a vendor client will hand
		// it straight to net/http.
		if seen[i].ctx == nil {
			t.Errorf("record %d arrived with a nil context", i)
		}
		if traceOf(seen[i].ctx) != "" {
			t.Errorf("record %d invented a trace: %q", i, traceOf(seen[i].ctx))
		}
	}
	if traceOf(seen[4].ctx) != "explicit" {
		t.Errorf("the explicit Log call lost its context")
	}
}

// A LogFunc must survive being bound, which is the shape a real host
// deployment ends up with: one function, wired into Config.Logger, called
// through the engine's per-call binding.
func TestLogFuncThroughForContext(t *testing.T) {
	var seen []record
	sink := LogFunc(func(ctx context.Context, level Level, msg string, fields map[string]string) {
		seen = append(seen, record{level: level, ctx: ctx})
	})

	ForContext(traceContext("trace-1"), sink).Info("m", nil)

	if len(seen) != 1 {
		t.Fatalf("got %d records, want 1", len(seen))
	}
	if traceOf(seen[0].ctx) != "trace-1" {
		t.Errorf("sink saw trace %q, want %q", traceOf(seen[0].ctx), "trace-1")
	}
}

func TestEmitPrefersTheContextMethod(t *testing.T) {
	sink := &ctxLogger{}

	emit(traceContext("via-emit"), sink, LevelInfo, "m", nil)

	if sink.bare != 0 {
		t.Fatalf("emit used a context-free method on a ContextLogger")
	}
	if traceOf(sink.last().ctx) != "via-emit" {
		t.Errorf("emit lost the context")
	}
}

func TestEmitRoutesAndClampsLevels(t *testing.T) {
	cases := []struct {
		in   Level
		want Level
	}{
		{LevelDebug, LevelDebug},
		{LevelInfo, LevelInfo},
		{LevelWarn, LevelWarn},
		{LevelError, LevelError},
		// Out of range is clamped, never dropped: a record with a level
		// nobody recognizes is still a record.
		{Level(-7), LevelDebug},
		{Level(99), LevelError},
	}
	for _, c := range cases {
		plain := &plainLogger{}
		emit(context.Background(), plain, c.in, "m", nil)
		if len(plain.records) != 1 {
			t.Fatalf("emit at level %d produced %d records, want 1", c.in, len(plain.records))
		}
		if plain.records[0].level != c.want {
			t.Errorf("emit at level %d landed on %v, want %v", c.in, plain.records[0].level, c.want)
		}
	}
}

func TestNopLoggerDiscardsEverythingWithoutPanicking(t *testing.T) {
	nop := NewNopLogger()
	nop.Debug("d", nil)
	nop.Info("i", map[string]string{"user_id": "u1"})
	nop.Warn("w", nil)
	nop.Error("e", nil)
	nop.Log(nil, LevelError, "e", nil) //lint:ignore SA1012 under test

	// And it must be visible as a ContextLogger, so ForContext does not
	// treat a deliberately quiet logger as a legacy one.
	if _, ok := Logger(nop).(ContextLogger); !ok {
		t.Errorf("NopLogger does not implement ContextLogger")
	}
}
