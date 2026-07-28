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
		Level:     level,
		Message:   msg,
		Fields:    fields,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
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
