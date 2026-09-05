package logger

import "strings"

// Level names the severity of one record. It exists because Logger's
// four methods are not enough on their own to build the two things
// shipping logs off the machine needs: a filter that drops records
// below a threshold before a vendor bills for them, and a single
// context-carrying method a host can implement once instead of four
// times over. Both need severity as a value rather than as a choice of
// method.
//
// Ordered least to most severe, so comparisons work:
// LevelDebug < LevelInfo < LevelWarn < LevelError.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// String returns the same lowercase word ConsoleJSONLogger writes in
// its "level" field, so a host's own sink can label a record the same
// way without keeping a second mapping table.
//
// Values outside the four constants clamp to the nearest end rather
// than printing a number. Everything in this package that dispatches on
// a Level clamps the same way, for the same reason: a record with an
// unrecognized severity is still a record, and losing it would be worse
// than filing it one step off.
func (l Level) String() string {
	switch clamp(l) {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	default:
		return "error"
	}
}

// clamp bounds a Level to the four constants. Every place in this
// package that dispatches on or compares a Level runs it through here
// first, so an unrecognized severity is treated one consistent way —
// filed at the nearest end — rather than being dropped by the filter and
// kept by the sink, or the reverse.
func clamp(l Level) Level {
	switch {
	case l < LevelDebug:
		return LevelDebug
	case l > LevelError:
		return LevelError
	}
	return l
}

// ParseLevel turns a configured string — LOG_LEVEL=info, a YAML field,
// a command-line flag — into a Level, so NewLevelFilter can be driven
// from configuration without every host writing the same four-case
// switch. Case and surrounding space are ignored, and "warning"/"err"
// are accepted alongside "warn"/"error" because both spellings are in
// wide use and neither is ambiguous.
//
// The returned Level is meaningless when err is non-nil: it is the zero
// value, not a fallback. Choosing one here would be choosing wrong in
// one direction or the other — defaulting a typo to debug quietly
// multiplies a vendor bill, and defaulting it to error quietly throws
// away the records someone was trying to keep.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error", "err":
		return LevelError, nil
	}
	return LevelDebug, ErrUnknownLevel
}
