package logger

import "context"

// LevelFilter drops records below a threshold before they reach the
// Logger it wraps. Nothing in the engine consults it: filtering is a
// property of one sink, not of the engine, which is why this is a
// wrapper and not a Config field. Wrap the sink that needs it and leave
// the others alone.
//
// It exists for cloud logging specifically. Hosted aggregators bill by
// ingested volume, and a login flow that is working correctly still
// emits debug and info records nobody will ever read. Dropping those at
// the boundary is the difference between a bill that tracks incidents
// and one that tracks traffic:
//
//	logger.NewLevelFilter(vendorSink, logger.LevelWarn)
//
// Set the threshold from configuration with ParseLevel, so it can be
// turned down during an incident without a deploy.
//
// A LevelFilter is a ContextLogger regardless of what it wraps, and
// forwards the context through. That is not incidental: a filter that
// forwarded through the four bare methods instead would silently strip
// the trace ID off every record it passed, so filtering by level would
// quietly cost the correlation the sink was chosen for.
type LevelFilter struct {
	inner Logger
	min   Level
}

// NewLevelFilter wraps inner, discarding everything below min. A min
// outside the four Level constants is clamped rather than rejected:
// there is no error return to use, and clamping is what every other
// Level comparison in this package does.
//
// A nil inner collapses to NopLogger rather than panicking on the first
// record. That is a wiring mistake either way, but a nil dereference
// inside a log statement would take down the login that was only trying
// to mention something.
func NewLevelFilter(inner Logger, min Level) *LevelFilter {
	if inner == nil {
		inner = NewNopLogger()
	}
	return &LevelFilter{inner: inner, min: clamp(min)}
}

// Min reports the threshold in force, for a host app that wants to log
// its own records through the same gate.
func (f *LevelFilter) Min() Level { return f.min }

// Enabled reports whether a record at this level would be forwarded.
// Worth checking before building an expensive fields map that is about
// to be discarded.
func (f *LevelFilter) Enabled(level Level) bool { return clamp(level) >= f.min }

func (f *LevelFilter) Debug(msg string, fields map[string]string) {
	f.Log(context.Background(), LevelDebug, msg, fields)
}

func (f *LevelFilter) Info(msg string, fields map[string]string) {
	f.Log(context.Background(), LevelInfo, msg, fields)
}

func (f *LevelFilter) Warn(msg string, fields map[string]string) {
	f.Log(context.Background(), LevelWarn, msg, fields)
}

func (f *LevelFilter) Error(msg string, fields map[string]string) {
	f.Log(context.Background(), LevelError, msg, fields)
}

func (f *LevelFilter) Log(ctx context.Context, level Level, msg string, fields map[string]string) {
	if !f.Enabled(level) {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	emit(ctx, f.inner, clamp(level), msg, fields)
}

var _ ContextLogger = (*LevelFilter)(nil)
