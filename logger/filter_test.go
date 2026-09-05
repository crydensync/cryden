package logger

import (
	"context"
	"testing"
)

func TestLevelFilterDropsBelowTheThreshold(t *testing.T) {
	sink := &plainLogger{}
	filter := NewLevelFilter(sink, LevelWarn)

	filter.Debug("d", nil)
	filter.Info("i", nil)
	filter.Warn("w", nil)
	filter.Error("e", nil)

	if len(sink.records) != 2 {
		t.Fatalf("got %d records through a warn filter, want 2: %v", len(sink.records), sink.records)
	}
	if sink.records[0].level != LevelWarn || sink.records[1].level != LevelError {
		t.Errorf("wrong records survived: %v", sink.records)
	}
}

func TestLevelFilterAtDebugPassesEverything(t *testing.T) {
	sink := &plainLogger{}
	filter := NewLevelFilter(sink, LevelDebug)

	filter.Debug("d", nil)
	filter.Info("i", nil)
	filter.Warn("w", nil)
	filter.Error("e", nil)

	if len(sink.records) != 4 {
		t.Errorf("got %d records through a debug filter, want 4", len(sink.records))
	}
}

func TestLevelFilterAtErrorKeepsOnlyErrors(t *testing.T) {
	sink := &plainLogger{}
	filter := NewLevelFilter(sink, LevelError)

	filter.Debug("d", nil)
	filter.Info("i", nil)
	filter.Warn("w", nil)
	filter.Error("e", nil)

	if len(sink.records) != 1 || sink.records[0].level != LevelError {
		t.Errorf("got %v, want one error record", sink.records)
	}
}

// The trap this wrapper has to avoid: filtering must not cost the
// context, or a host would have to choose between a cheap bill and
// correlated traces.
func TestLevelFilterKeepsTheContext(t *testing.T) {
	sink := &ctxLogger{}
	filter := NewLevelFilter(sink, LevelInfo)

	ForContext(traceContext("trace-9"), filter).Warn("login: failed attempt", map[string]string{"ip": "1.2.3.4"})

	if len(sink.records) != 1 {
		t.Fatalf("got %d records, want 1", len(sink.records))
	}
	if sink.bare != 0 {
		t.Errorf("the filter forwarded through a context-free method")
	}
	if got := traceOf(sink.last().ctx); got != "trace-9" {
		t.Errorf("sink saw trace %q, want %q", got, "trace-9")
	}
	if sink.last().fields["ip"] != "1.2.3.4" {
		t.Errorf("fields did not survive the filter: %v", sink.last().fields)
	}
}

func TestLevelFilterIsVisibleAsAContextLogger(t *testing.T) {
	// ForContext has to recognize the wrapper, not just what it wraps.
	filter := NewLevelFilter(&plainLogger{}, LevelInfo)
	if _, ok := Logger(filter).(ContextLogger); !ok {
		t.Fatal("LevelFilter does not implement ContextLogger")
	}
	if bound := ForContext(traceContext("t"), filter); bound == Logger(filter) {
		t.Error("ForContext returned the filter unwrapped, so no context would be bound")
	}
}

func TestLevelFilterClampsOutOfRangeLevels(t *testing.T) {
	// A record whose level nobody recognizes is filed at the nearest end,
	// not discarded: dropping it silently is the one behavior that loses
	// information.
	sink := &plainLogger{}
	filter := NewLevelFilter(sink, LevelDebug)

	filter.Log(context.Background(), Level(-7), "underflow", nil)
	filter.Log(context.Background(), Level(99), "overflow", nil)

	if len(sink.records) != 2 {
		t.Fatalf("got %d records, want 2", len(sink.records))
	}
	if sink.records[0].level != LevelDebug || sink.records[1].level != LevelError {
		t.Errorf("clamping went wrong: %v", sink.records)
	}
}

func TestLevelFilterClampsItsOwnThreshold(t *testing.T) {
	if got := NewLevelFilter(&plainLogger{}, Level(99)).Min(); got != LevelError {
		t.Errorf("a threshold of 99 became %v, want %v", got, LevelError)
	}
	if got := NewLevelFilter(&plainLogger{}, Level(-3)).Min(); got != LevelDebug {
		t.Errorf("a threshold of -3 became %v, want %v", got, LevelDebug)
	}
}

func TestLevelFilterEnabled(t *testing.T) {
	filter := NewLevelFilter(&plainLogger{}, LevelWarn)
	cases := map[Level]bool{
		LevelDebug: false,
		LevelInfo:  false,
		LevelWarn:  true,
		LevelError: true,
	}
	for level, want := range cases {
		if got := filter.Enabled(level); got != want {
			t.Errorf("Enabled(%v) = %v, want %v", level, got, want)
		}
	}
}

func TestLevelFilterSurvivesANilInner(t *testing.T) {
	// A wiring mistake must not turn a log statement into a panic inside
	// whatever call was being served.
	filter := NewLevelFilter(nil, LevelDebug)
	filter.Error("nothing to write to", nil)
	filter.Log(nil, LevelError, "nor a context to write it with", nil) //lint:ignore SA1012 under test
}

func TestLevelFilterNestsWithoutSurprises(t *testing.T) {
	// Two filters in a chain: the stricter one wins wherever it sits.
	sink := &plainLogger{}
	filter := NewLevelFilter(NewLevelFilter(sink, LevelError), LevelInfo)

	filter.Info("i", nil)
	filter.Error("e", nil)

	if len(sink.records) != 1 || sink.records[0].level != LevelError {
		t.Errorf("got %v, want only the error record", sink.records)
	}
}
