package logger

import (
	"context"
	"fmt"
	"os"
)

// MultiLogger writes every record to several loggers. It is what makes
// shipping logs somewhere an addition rather than a replacement: the
// full-detail JSON line stays on stdout, where the host app's own
// tooling can already reach it, while a second copy — filtered, and with
// the personal data taken out — goes to whatever hosted sink the host
// has bought.
//
// Composition order is the whole design, and it belongs inside the
// fan-out rather than around it:
//
//	logger.NewMultiLogger(
//		logger.NewConsoleJSONLogger(),
//		logger.NewLevelFilter(logger.NewMaskingRedactor(vendorSink), logger.LevelInfo),
//	)
//
// Wrapped that way, the local copy keeps the IP address that makes an
// incident debuggable and only the copy leaving the building loses it.
// Wrapping the MultiLogger itself in the redactor instead would strip
// both.
//
// The fields map is passed to each sink as-is rather than copied per
// sink: a Logger must treat its arguments as read-only, which the four
// implementations in this package do, and copying every map for every
// sink would cost an allocation on every record to defend against a bug
// nobody has.
type MultiLogger struct {
	loggers []Logger
}

// NewMultiLogger fans each record out to every logger given, in the
// order given.
//
// Nil arguments are skipped, so a sink that only exists in production
// can be passed straight through without a branch at the call site:
//
//	logger.NewMultiLogger(logger.NewConsoleJSONLogger(), vendorSink)
//
// Only an untyped nil is caught that way. A nil *MySink stored in a
// Logger is not a nil interface and will be called like any other sink —
// the same trap Config.Geolocator has, and the reason a host should pass
// the interface value it actually has rather than a typed nil.
//
// Returns the surviving logger unwrapped when only one is left, since a
// one-sink fan-out is just overhead, and a NopLogger when none is. That
// last case is the only way to get a silent engine out of this package,
// and it is deliberate: something has to be returned, and a fan-out that
// looks configured while writing nowhere is worse than one that is
// visibly empty.
func NewMultiLogger(loggers ...Logger) Logger {
	kept := make([]Logger, 0, len(loggers))
	for _, l := range loggers {
		if l != nil {
			kept = append(kept, l)
		}
	}
	switch len(kept) {
	case 0:
		return NewNopLogger()
	case 1:
		return kept[0]
	}
	return &MultiLogger{loggers: kept}
}

func (m *MultiLogger) Debug(msg string, fields map[string]string) {
	m.Log(context.Background(), LevelDebug, msg, fields)
}

func (m *MultiLogger) Info(msg string, fields map[string]string) {
	m.Log(context.Background(), LevelInfo, msg, fields)
}

func (m *MultiLogger) Warn(msg string, fields map[string]string) {
	m.Log(context.Background(), LevelWarn, msg, fields)
}

func (m *MultiLogger) Error(msg string, fields map[string]string) {
	m.Log(context.Background(), LevelError, msg, fields)
}

func (m *MultiLogger) Log(ctx context.Context, level Level, msg string, fields map[string]string) {
	if ctx == nil {
		ctx = context.Background()
	}
	for _, l := range m.loggers {
		writeOne(ctx, l, level, msg, fields)
	}
}

var _ ContextLogger = (*MultiLogger)(nil)

// writeOne isolates one sink's failure from the rest, which is the only
// promise a fan-out can make: a vendor client that panics mid-flush must
// not cost the copy on stdout, and must not take down the login that was
// merely being logged. Recovery is scoped to here and nowhere else in
// this package — an engine holding a single broken Logger should still
// fail loudly, since there is no second sink for the evidence to survive
// in.
//
// The panic is reported to stderr rather than swallowed. Stderr needs no
// wiring, cannot recurse back into the logger that just failed, and is
// where the runtime would have printed this anyway.
func writeOne(ctx context.Context, l Logger, level Level, msg string, fields map[string]string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "logger: a sink panicked on a %s record (%q) and that record is lost: %v\n", level, msg, r)
		}
	}()
	emit(ctx, l, level, msg, fields)
}
