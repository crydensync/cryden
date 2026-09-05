package logger

import (
	"encoding/json"
	"os"
	"time"
)

// ConsoleJSONLogger is the v2 Logger implementation. It writes one
// JSON object per line to stdout — the standard 12-factor pattern,
// letting the consuming app's own infra (Docker, systemd, a log
// agent/sidecar) route output to file/cloud as needed. This package
// never writes to disk or calls a cloud logging API directly.
//
// It implements Logger only, not ContextLogger: there is no trace ID it
// could read out of a context, since the key that holds one belongs to
// the host app. ForContext hands it back unchanged, which is why wiring
// it costs nothing and why it is still the default. To send these
// records somewhere else as well, see this package's own doc comment —
// the answer is a MultiLogger, not a second ConsoleJSONLogger.
type ConsoleJSONLogger struct{}

func NewConsoleJSONLogger() *ConsoleJSONLogger {
	return &ConsoleJSONLogger{}
}

type logLine struct {
	Level     string            `json:"level"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
	Timestamp string            `json:"timestamp"`
}

func (l *ConsoleJSONLogger) write(level, msg string, fields map[string]string) {
	line := logLine{
		Level:   level,
		Message: msg,
		Fields:  fields,
		// Nano, not plain RFC3339: one login emits dozens of records, and
		// at second precision they arrive with identical timestamps, so
		// nothing downstream can order them. A hosted sink sorting by
		// timestamp is where that stops being cosmetic.
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}
	b, err := json.Marshal(line)
	if err != nil {
		// Marshaling a small struct of strings should never fail; if it
		// somehow does, fall back to a plain-text line rather than
		// silently dropping the log.
		os.Stdout.WriteString(level + ": " + msg + "\n")
		return
	}
	os.Stdout.Write(append(b, '\n'))
}

func (l *ConsoleJSONLogger) Debug(msg string, fields map[string]string) {
	l.write("debug", msg, fields)
}

func (l *ConsoleJSONLogger) Info(msg string, fields map[string]string) {
	l.write("info", msg, fields)
}

func (l *ConsoleJSONLogger) Warn(msg string, fields map[string]string) {
	l.write("warn", msg, fields)
}

func (l *ConsoleJSONLogger) Error(msg string, fields map[string]string) {
	l.write("error", msg, fields)
}
