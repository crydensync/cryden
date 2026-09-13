package logger

import "context"

// NopLogger discards every record. It exists for three jobs: tests that
// want the engine quiet (session/ and auth/ each hand-roll one of these
// today), a host app that genuinely wants no operational logging, and
// NewMultiLogger, which needs something well-defined to return when
// every sink it was handed turns out to be nil.
//
// It implements ContextLogger as well as Logger, so wrapping it in
// ForContext is not a silent no-op that hides a wiring mistake during
// testing.
type NopLogger struct{}

func NewNopLogger() *NopLogger { return &NopLogger{} }

func (*NopLogger) Debug(string, map[string]string) {}
func (*NopLogger) Info(string, map[string]string)  {}
func (*NopLogger) Warn(string, map[string]string)  {}
func (*NopLogger) Error(string, map[string]string) {}

func (*NopLogger) Log(context.Context, Level, string, map[string]string) {}

var _ ContextLogger = (*NopLogger)(nil)
