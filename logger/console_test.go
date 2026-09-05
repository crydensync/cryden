package logger

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestConsoleJSONLoggerWritesOneObjectPerLine(t *testing.T) {
	stdout, restore := captureStdout(t)
	defer restore()

	log := NewConsoleJSONLogger()
	log.Debug("d", nil)
	log.Info("i", nil)
	log.Warn("w", nil)
	log.Error("login failed", map[string]string{"ip": "203.0.113.7"})

	lines := decodeLines(t, stdout())
	if len(lines) != 4 {
		t.Fatalf("want 4 lines, got %d", len(lines))
	}

	// The level words are the same four Level.String() produces, which is
	// what lets a host filter on a Level and grep for what it sees.
	for i, level := range []Level{LevelDebug, LevelInfo, LevelWarn, LevelError} {
		if lines[i].Level != level.String() {
			t.Errorf("line %d says level %q, want %q", i, lines[i].Level, level.String())
		}
	}
	if lines[3].Message != "login failed" {
		t.Errorf("message came out as %q", lines[3].Message)
	}
	if lines[3].Fields["ip"] != "203.0.113.7" {
		t.Errorf("fields came out as %v", lines[3].Fields)
	}
	if lines[0].Fields != nil {
		t.Errorf("a record with no fields should carry no fields key, got %v", lines[0].Fields)
	}
}

// The reason the format is RFC3339Nano: a single login emits dozens of
// records, and at second precision they all carry the same timestamp,
// which leaves a sink sorting by it with nothing to sort by.
func TestConsoleJSONLoggerTimestampsCanOrderRecords(t *testing.T) {
	stdout, restore := captureStdout(t)
	defer restore()

	log := NewConsoleJSONLogger()
	for i := 0; i < 5; i++ {
		log.Info("burst", nil)
	}

	lines := decodeLines(t, stdout())
	seen := make(map[string]struct{}, len(lines))
	var previous time.Time
	for i, line := range lines {
		at, err := time.Parse(time.RFC3339Nano, line.Timestamp)
		if err != nil {
			t.Fatalf("line %d timestamp %q does not parse: %v", i, line.Timestamp, err)
		}
		if at.Before(previous) {
			t.Errorf("line %d went backwards in time: %q", i, line.Timestamp)
		}
		previous = at
		seen[line.Timestamp] = struct{}{}
	}
	if len(seen) < 2 {
		t.Fatalf("all %d records share one timestamp (%v) — nothing downstream can order them", len(lines), seen)
	}
}

func decodeLines(t *testing.T, out string) []logLine {
	t.Helper()
	var lines []logLine
	for _, raw := range strings.Split(strings.TrimSpace(out), "\n") {
		if raw == "" {
			continue
		}
		var line logLine
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("line %q is not JSON: %v", raw, err)
		}
		lines = append(lines, line)
	}
	return lines
}

// captureStdout is captureStderr's counterpart, for the one logger that
// writes to stdout on purpose.
func captureStdout(t *testing.T) (read func() string, restore func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating a pipe: %v", err)
	}
	original := os.Stdout
	os.Stdout = w
	return func() string {
		w.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("reading captured stdout: %v", err)
		}
		return string(out)
	}, func() { os.Stdout = original }
}
