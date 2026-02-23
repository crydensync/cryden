package tests

import (
    "context"
    "testing"
    "time"
    
    "github.com/raymondproguy/credensync/core"
)

func TestConsoleAuditLogger(t *testing.T) {
    logger := core.NewConsoleAuditLogger()
    ctx := context.Background()
    
    t.Run("log entry", func(t *testing.T) {
        entry := core.AuditEntry{
            Timestamp: time.Now(),
            UserID:    "user_123",
            Action:    core.ActionSignInSuccess,
            Status:    "SUCCESS",
            IPAddress: "192.168.1.1",
            UserAgent: "test-agent",
        }
        
        err := logger.Log(ctx, entry)
        if err != nil {
            t.Errorf("Expected no error, got %v", err)
        }
    })
    
    t.Run("log failed attempt", func(t *testing.T) {
        entry := core.AuditEntry{
            Timestamp: time.Now(),
            UserID:    "user_123",
            Action:    core.ActionSignInFailed,
            Status:    "FAILED",
            Error:     "wrong password",
            IPAddress: "192.168.1.1",
        }
        
        err := logger.Log(ctx, entry)
        if err != nil {
            t.Errorf("Expected no error, got %v", err)
        }
    })
    
    logger.Close()
}

func TestNoopAuditLogger(t *testing.T) {
    logger := core.NewNoopAuditLogger()
    ctx := context.Background()
    
    t.Run("log does nothing", func(t *testing.T) {
        entry := core.AuditEntry{
            Timestamp: time.Now(),
            UserID:    "user_123",
            Action:    core.ActionSignUp,
            Status:    "SUCCESS",
        }
        
        err := logger.Log(ctx, entry)
        if err != nil {
            t.Errorf("Expected no error, got %v", err)
        }
    })
    
    logger.Close()
}
