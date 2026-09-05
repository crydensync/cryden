package logger

import (
	"errors"
	"testing"
)

func TestLevelOrdering(t *testing.T) {
	// The filter and every wrapper in this package compare levels, so
	// the order is load-bearing, not cosmetic.
	if !(LevelDebug < LevelInfo && LevelInfo < LevelWarn && LevelWarn < LevelError) {
		t.Fatalf("levels are not ordered debug < info < warn < error: %d %d %d %d",
			LevelDebug, LevelInfo, LevelWarn, LevelError)
	}
}

func TestLevelString(t *testing.T) {
	cases := []struct {
		level Level
		want  string
	}{
		{LevelDebug, "debug"},
		{LevelInfo, "info"},
		{LevelWarn, "warn"},
		{LevelError, "error"},
		// Out of range in both directions clamps rather than printing a
		// number — same rule emit() follows when routing a record.
		{Level(-7), "debug"},
		{Level(99), "error"},
	}
	for _, c := range cases {
		if got := c.level.String(); got != c.want {
			t.Errorf("Level(%d).String() = %q, want %q", c.level, got, c.want)
		}
	}
}

func TestLevelStringMatchesConsoleOutput(t *testing.T) {
	// ConsoleJSONLogger writes these four words in its "level" field. If
	// the two ever disagree, a host reading both sinks sees one event
	// labelled two ways.
	for _, want := range []string{"debug", "info", "warn", "error"} {
		level, err := ParseLevel(want)
		if err != nil {
			t.Fatalf("ParseLevel(%q) failed: %v", want, err)
		}
		if got := level.String(); got != want {
			t.Errorf("round trip of %q produced %q", want, got)
		}
	}
}

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want Level
	}{
		{"debug", LevelDebug},
		{"info", LevelInfo},
		{"warn", LevelWarn},
		{"warning", LevelWarn},
		{"error", LevelError},
		{"err", LevelError},
		{"INFO", LevelInfo},
		{"  Warn  ", LevelWarn},
	}
	for _, c := range cases {
		got, err := ParseLevel(c.in)
		if err != nil {
			t.Errorf("ParseLevel(%q) returned an unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseLevelRejectsUnknownNames(t *testing.T) {
	// Negative cases: a typo, a level name from another library, and
	// empty. None of them may silently become a working configuration.
	for _, in := range []string{"", "verbose", "trace", "fatal", "panic", "infoo", "notice"} {
		level, err := ParseLevel(in)
		if !errors.Is(err, ErrUnknownLevel) {
			t.Errorf("ParseLevel(%q) = (%v, %v), want ErrUnknownLevel", in, level, err)
		}
		if level != LevelDebug {
			t.Errorf("ParseLevel(%q) returned %v alongside its error; the documented value is the zero one", in, level)
		}
	}
}
