package core

import (
    "context"
    "time"
)

// GetUser retrieves a user by ID
func (e *Engine) GetUser(ctx context.Context, userID string) (*User, error) {
    return e.users.GetByID(ctx, userID)
}

// GetUserByEmail retrieves a user by email
func (e *Engine) GetUserByEmail(ctx context.Context, email string) (*User, error) {
    return e.users.GetByEmail(ctx, email)
}

// ChangePassword updates user's password and logs out all devices
func (e *Engine) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
    // Get user
    user, err := e.users.GetByID(ctx, userID)
    if err != nil {
        return err
    }

    // Verify old password
    if err := e.hasher.Compare(oldPassword, user.PasswordHash); err != nil {
        e.auditLogger.Log(ctx, AuditEntry{
            Timestamp: time.Now(),
            UserID:    userID,
            Action:    ActionPasswordChange,
            Status:    "FAILED",
            Error:     "wrong old password",
        })
        return ErrInvalidCredentials
    }

    // Validate new password
    if err := ValidatePassword(newPassword, e.config.PasswordPolicy); err != nil {
        return err
    }

    // Hash new password
    newHash, err := e.hasher.Hash(newPassword)
    if err != nil {
        return err
    }

    // Update in database
    if err := e.users.UpdatePassword(ctx, userID, newHash); err != nil {
        return err
    }

    // Logout all devices (security best practice)
    e.sessions.RevokeAllForUser(ctx, userID)

    e.auditLogger.Log(ctx, AuditEntry{
        Timestamp: time.Now(),
        UserID:    userID,
        Action:    ActionPasswordChange,
        Status:    "SUCCESS",
    })

    return nil
}

// ChangeEmail updates user's email
func (e *Engine) ChangeEmail(ctx context.Context, userID, newEmail string) error {
    // Validate email
    if err := ValidateEmail(newEmail); err != nil {
        return err
    }

    // Check if email already exists
    existing, err := e.users.GetByEmail(ctx, newEmail)
    if err != nil && err != ErrUserNotFound {
        return err
    }
    if existing != nil {
        return ErrUserExists
    }

    // Update email
    if err := e.users.UpdateEmail(ctx, userID, newEmail); err != nil {
        return err
    }

    e.auditLogger.Log(ctx, AuditEntry{
        Timestamp: time.Now(),
        UserID:    userID,
        Action:    ActionEmailChange,
        Status:    "SUCCESS",
        Metadata: map[string]interface{}{
            "new_email": newEmail,
        },
    })

    return nil
}

// DeleteAccount removes user and all sessions
func (e *Engine) DeleteAccount(ctx context.Context, userID string) error {
    // Delete all sessions first
    e.sessions.RevokeAllForUser(ctx, userID)

    // Delete user
    if err := e.users.Delete(ctx, userID); err != nil {
        return err
    }

    e.auditLogger.Log(ctx, AuditEntry{
        Timestamp: time.Now(),
        UserID:    userID,
        Action:    ActionAccountDelete,
        Status:    "SUCCESS",
    })

    return nil
}
