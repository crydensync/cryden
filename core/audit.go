package core

import (
	"context"
	"fmt"
	"time"
)

// AuditAction Represent what happened
type AuditAction string

const (
	ActionSignUp         AuditAction = "SIGN_UP"
	ActionSignInSuccess  AuditAction = "SIGN_IN_SUCCESS"
	ActionSignInFailed   AuditAction = "SIGN_IN_FAILED"
	ActionSignOut        AuditAction = "SIGN_OUT"
	ActionSignOutAll     AuditAction = "SIGN_OUT_ALL"
	ActionPasswordChange AuditAction = "PASSWORD_CHANGE"
	ActionEmailChange    AuditAction = "EMAIL_CHANGE"
	ActionAccountDelete  AuditAction = "ACCOUNT_DELETE"
	ActionTokonRefresh   AuditAction = "TOKEN_REFRESH"
	ActionRateLimited    AuditAction = "RATE_LIMITED"
)

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	Timestamp time.Time
	UserID    string
	Action    AuditAction
	Status    string
	Error     string
	IPAddress string
	UserAgent string
	Metadata  map[string]interface{}
}

// AuditLogger defines how to log events
type AuditLogger interface {
	Log(ctx context.Context, entry AuditEntry) error
	Close() error
}

// ConsoleAuditLogger prints to the console
type ConsoleAuditLogger struct{}

func NewConsoleAuditLogger() *ConsoleAuditLogger {
	return &ConsoleAuditLogger{}
}
func (l *ConsoleAuditLogger) Log(ctx context.Context, entry AuditEntry) error {
	timestamp := entry.Timestamp.Format("2006-01-02 15:04:05")
	fmt.Printf("[AUDIT] %s | User: %s | Action: %s | Status: %s\n", timestamp, entry.UserID, entry.Action, entry.Status)

	if entry.Error != "" {
		fmt.Printf(" Error: %s\n", entry.Error)
	}
	if entry.IPAddress != "" {
		fmt.Printf(" IP: %s\n", entry.IPAddress)
	}
	if len(entry.Metadata) > 0 {
		fmt.Printf(" Metadata: %v\n", entry.Metadata)
	}

	return nil
}

func (l *ConsoleAuditLogger) Close() error {
	return nil
}

// NoopAuditLogger dose nothing just for testing
type NoopAuditLogger struct{}

func NewNoopAuditLogger() *NoopAuditLogger {
	return &NoopAuditLogger{}
}

func (l *NoopAuditLogger) Log(ctx context.Context, entry AuditEntry) error {
	return nil
}

func (l *NoopAuditLogger) Close() error {
	return nil
}

// FileAuditLogger writes to a file
type FileAuditLogger struct {
	filePath string
}

func NewFileAuditLogger(filePath string) *FileAuditLogger {
	return &FileAuditLogger{filePath: filePath}
}

func (l *FileAuditLogger) Log(ctx context.Context, entry AuditEntry) error {
	timestamp := entry.Timestamp.Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("%s | %s | %s | %s | %s\n", timestamp, entry.UserID, entry.Action, entry.Error, entry.IPAddress)

	fmt.Printf("[FILE AUDIT] %s", line)

	return nil
}

func (l *FileAuditLogger) Close() error {
	return nil
}
