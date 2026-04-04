package tests

import (
    "context"
    "encoding/json"
    "os"
    "path/filepath"
    "testing"
    "time"

    "github.com/crydensync/cryden/internal/core"
    "github.com/crydensync/cryden/internal/stores/memory"
)

func TestFileAuditLogger(t *testing.T) {
    // Create temp directory for test logs
    tempDir := t.TempDir()
    logPath := filepath.Join(tempDir, "audit.log")

    // Create file logger
    logger, err := core.NewFileAuditLogger(logPath)
    if err != nil {
        t.Fatalf("Failed to create file logger: %v", err)
    }
    defer logger.Close()

    ctx := context.Background()

    // Log an entry
    entry := core.AuditEntry{
        Timestamp: time.Now(),
        UserID:    "user_123",
        Action:    core.ActionSignInSuccess,
        Status:    "SUCCESS",
        IPAddress: "192.168.1.1",
        Metadata: map[string]interface{}{
            "user_agent": "Mozilla/5.0",
        },
    }

    if err := logger.Log(ctx, entry); err != nil {
        t.Fatalf("Failed to log entry: %v", err)
    }

    // Read the log file
    data, err := os.ReadFile(logPath)
    if err != nil {
        t.Fatalf("Failed to read log file: %v", err)
    }

    // Parse JSON
    var loggedEntry core.AuditEntry
    if err := json.Unmarshal(data, &loggedEntry); err != nil {
        t.Fatalf("Failed to parse JSON: %v", err)
    }

    // Verify fields
    if loggedEntry.UserID != entry.UserID {
        t.Errorf("Expected UserID %s, got %s", entry.UserID, loggedEntry.UserID)
    }
    if loggedEntry.Action != entry.Action {
        t.Errorf("Expected Action %s, got %s", entry.Action, loggedEntry.Action)
    }
    if loggedEntry.IPAddress != entry.IPAddress {
        t.Errorf("Expected IPAddress %s, got %s", entry.IPAddress, loggedEntry.IPAddress)
    }
    if loggedEntry.Status != entry.Status {
        t.Errorf("Expected Status %s, got %s", entry.Status, loggedEntry.Status)
    }
}

func TestFileAuditLoggerWithEngine(t *testing.T) {
    // Create temp directory
    tempDir := t.TempDir()
    logPath := filepath.Join(tempDir, "auth.log")

    // Create file logger
    logger, err := core.NewFileAuditLogger(logPath)
    if err != nil {
        t.Fatalf("Failed to create logger: %v", err)
    }
    defer logger.Close()

    // Create engine with file logger
    userStore := memory.NewUserStore()
    sessionStore := memory.NewSessionStore()
    engine := core.New(userStore, sessionStore)
    engine.WithAuditLogger(logger)

    ctx := context.Background()

    // Perform signup (should log)
    _, err = engine.SignUp(ctx, "test@example.com", "Password123")
    if err != nil {
        t.Fatalf("SignUp failed: %v", err)
    }

    // Check log file was written
    data, err := os.ReadFile(logPath)
    if err != nil {
        t.Fatalf("Failed to read log file: %v", err)
    }

    if len(data) == 0 {
        t.Error("Log file is empty")
    }

    // Verify JSON format
    var entry core.AuditEntry
    if err := json.Unmarshal(data, &entry); err != nil {
        t.Errorf("Invalid JSON format: %v", err)
    }

    // Verify it's a signup event
    if entry.Action != core.ActionSignUp {
        t.Errorf("Expected Action SIGN_UP, got %s", entry.Action)
    }
}

func TestFileAuditLoggerRotation(t *testing.T) {
    tempDir := t.TempDir()
    logPath := filepath.Join(tempDir, "rotate.log")

    logger, err := core.NewFileAuditLogger(logPath)
    if err != nil {
        t.Fatalf("Failed to create logger: %v", err)
    }
    defer logger.Close()

    ctx := context.Background()

    // Write first entry
    err = logger.Log(ctx, core.AuditEntry{
        UserID: "user1",
        Action: "TEST_ENTRY_1",
        Status: "SUCCESS",
    })
    if err != nil {
        t.Fatalf("Failed to write first entry: %v", err)
    }

    // Rotate the log file
    if err := logger.Rotate(); err != nil {
        t.Fatalf("Rotation failed: %v", err)
    }

    // Write second entry after rotation
    err = logger.Log(ctx, core.AuditEntry{
        UserID: "user2",
        Action: "TEST_ENTRY_2",
        Status: "SUCCESS",
    })
    if err != nil {
        t.Fatalf("Failed to write second entry: %v", err)
    }

    // Read the log file
    data, err := os.ReadFile(logPath)
    if err != nil {
        t.Fatalf("Failed to read log file: %v", err)
    }

    // Should have two JSON lines (one per line)
    lines := 0
    for _, b := range data {
        if b == '\n' {
            lines++
        }
    }

    if lines < 2 {
        t.Errorf("Expected at least 2 log entries, got %d", lines)
    }
}

func TestFileAuditLoggerDirectoryCreation(t *testing.T) {
    tempDir := t.TempDir()
    // Create a nested path that doesn't exist yet
    logPath := filepath.Join(tempDir, "nested", "deep", "path", "audit.log")

    logger, err := core.NewFileAuditLogger(logPath)
    if err != nil {
        t.Fatalf("Failed to create logger with nested directory: %v", err)
    }
    defer logger.Close()

    // Check that directory was created
    if _, err := os.Stat(filepath.Dir(logPath)); os.IsNotExist(err) {
        t.Error("Directory was not created")
    }

    // Check that file exists
    if _, err := os.Stat(logPath); os.IsNotExist(err) {
        t.Error("Log file was not created")
    }
}

func TestMultipleFileLoggers(t *testing.T) {
    tempDir := t.TempDir()
    logPath1 := filepath.Join(tempDir, "log1.log")
    logPath2 := filepath.Join(tempDir, "log2.log")

    // Create two separate loggers
    logger1, err := core.NewFileAuditLogger(logPath1)
    if err != nil {
        t.Fatalf("Failed to create logger1: %v", err)
    }
    defer logger1.Close()

    logger2, err := core.NewFileAuditLogger(logPath2)
    if err != nil {
        t.Fatalf("Failed to create logger2: %v", err)
    }
    defer logger2.Close()

    ctx := context.Background()

    // Log to both
    logger1.Log(ctx, core.AuditEntry{UserID: "user1", Action: "LOG1"})
    logger2.Log(ctx, core.AuditEntry{UserID: "user2", Action: "LOG2"})

    // Verify both files have content
    data1, _ := os.ReadFile(logPath1)
    data2, _ := os.ReadFile(logPath2)

    if len(data1) == 0 {
        t.Error("Logger1 file is empty")
    }
    if len(data2) == 0 {
        t.Error("Logger2 file is empty")
    }
}
