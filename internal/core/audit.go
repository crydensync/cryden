package core

import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "sync"
    "time"
)

// ==================== Types ====================

// AuditAction represents what happened
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
    ActionTokenRefresh   AuditAction = "TOKEN_REFRESH"
    ActionRateLimited    AuditAction = "RATE_LIMITED"
)

// AuditEntry represents a single audit log entry
type AuditEntry struct {
    Timestamp time.Time              `json:"timestamp"`
    UserID    string                 `json:"user_id,omitempty"`
    Action    AuditAction            `json:"action"`
    Status    string                 `json:"status"`
    Error     string                 `json:"error,omitempty"`
    IPAddress string                 `json:"ip_address,omitempty"`
    UserAgent string                 `json:"user_agent,omitempty"`
    Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// AuditLogger defines how to log events
type AuditLogger interface {
    Log(ctx context.Context, entry AuditEntry) error
    Close() error
}

// ==================== Console Logger ====================

// ConsoleAuditLogger prints to the console
type ConsoleAuditLogger struct{}

// NewConsoleAuditLogger creates a new console audit logger
func NewConsoleAuditLogger() *ConsoleAuditLogger {
    return &ConsoleAuditLogger{}
}

// Log prints the audit entry to console
func (l *ConsoleAuditLogger) Log(ctx context.Context, entry AuditEntry) error {
    timestamp := entry.Timestamp.Format("2006-01-02 15:04:05")
    fmt.Printf("[AUDIT] %s | User: %s | Action: %s | Status: %s\n",
        timestamp, entry.UserID, entry.Action, entry.Status)

    if entry.Error != "" {
        fmt.Printf("  Error: %s\n", entry.Error)
    }
    if entry.IPAddress != "" {
        fmt.Printf("  IP: %s\n", entry.IPAddress)
    }
    if len(entry.Metadata) > 0 {
        fmt.Printf("  Metadata: %v\n", entry.Metadata)
    }

    return nil
}

// Close closes the logger (no-op for console)
func (l *ConsoleAuditLogger) Close() error {
    return nil
}

// ==================== Noop Logger ====================

// NoopAuditLogger does nothing (for testing)
type NoopAuditLogger struct{}

// NewNoopAuditLogger creates a new no-op audit logger
func NewNoopAuditLogger() *NoopAuditLogger {
    return &NoopAuditLogger{}
}

// Log does nothing
func (l *NoopAuditLogger) Log(ctx context.Context, entry AuditEntry) error {
    return nil
}

// Close does nothing
func (l *NoopAuditLogger) Close() error {
    return nil
}

// ==================== File Logger ====================

// FileAuditLogger writes audit logs to a file in JSON format
type FileAuditLogger struct {
    mu       sync.Mutex
    file     *os.File
    encoder  *json.Encoder
    filePath string
}

// NewFileAuditLogger creates a new file audit logger
func NewFileAuditLogger(filePath string) (*FileAuditLogger, error) {
    // Create directory if it doesn't exist
    dir := filepath.Dir(filePath)
    if err := os.MkdirAll(dir, 0755); err != nil {
        return nil, fmt.Errorf("failed to create log directory: %w", err)
    }

    // Open file for appending
    file, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil {
        return nil, fmt.Errorf("failed to open log file: %w", err)
    }

    return &FileAuditLogger{
        file:     file,
        encoder:  json.NewEncoder(file),
        filePath: filePath,
    }, nil
}

// Log writes an audit entry to the file
func (l *FileAuditLogger) Log(ctx context.Context, entry AuditEntry) error {
    l.mu.Lock()
    defer l.mu.Unlock()

    // Add timestamp if not set
    if entry.Timestamp.IsZero() {
        entry.Timestamp = time.Now()
    }

    // Write JSON line
    if err := l.encoder.Encode(entry); err != nil {
        return fmt.Errorf("failed to write audit log: %w", err)
    }

    return nil
}

// Close closes the log file
func (l *FileAuditLogger) Close() error {
    l.mu.Lock()
    defer l.mu.Unlock()

    if l.file != nil {
        return l.file.Close()
    }
    return nil
}

// Rotate closes and reopens the log file (for log rotation)
func (l *FileAuditLogger) Rotate() error {
    l.mu.Lock()
    defer l.mu.Unlock()

    // Close current file
    if err := l.file.Close(); err != nil {
        return err
    }

    // Reopen file
    file, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil {
        return err
    }

    l.file = file
    l.encoder = json.NewEncoder(file)
    return nil
}
