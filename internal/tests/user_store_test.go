package tests

import (
	"context"
	"testing"

	"github.com/raymondproguy/credensync/core"
	"github.com/raymondproguy/credensync/stores/memory"
)

func TestMemoryUserStore(t *testing.T) {
	// Create store
	store := memory.NewUserStore()
	ctx := context.Background()

	t.Run("Create and Get user", func(t *testing.T) {
		// Create user
		user, err := store.Create(ctx, "test@example.com", "hash123")
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		if user.Email != "test@example.com" {
			t.Errorf("Expected email test@example.com, got %s", user.Email)
		}

		if user.PasswordHash != "hash123" {
			t.Errorf("Expected hash hash123, got %s", user.PasswordHash)
		}

		// Get by email
		found, err := store.GetByEmail(ctx, "test@example.com")
		if err != nil {
			t.Fatalf("Failed to get user by email: %v", err)
		}

		if found.ID != user.ID {
			t.Errorf("Expected ID %s, got %s", user.ID, found.ID)
		}

		// Get by ID
		found, err = store.GetByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("Failed to get user by ID: %v", err)
		}

		if found.Email != user.Email {
			t.Errorf("Expected email %s, got %s", user.Email, found.Email)
		}
	})

	t.Run("Create duplicate user", func(t *testing.T) {
		// First creation should work
		_, err := store.Create(ctx, "duplicate@example.com", "hash")
		if err != nil {
			t.Fatalf("First creation failed: %v", err)
		}

		// Second creation with same email should fail
		_, err = store.Create(ctx, "duplicate@example.com", "hash")
		if err != core.ErrUserExists {
			t.Errorf("Expected ErrUserExists, got %v", err)
		}
	})

	t.Run("Get nonexistent user", func(t *testing.T) {
		_, err := store.GetByEmail(ctx, "nonexistent@example.com")
		if err != core.ErrUserNotFound {
			t.Errorf("Expected ErrUserNotFound, got %v", err)
		}
	})

	t.Run("Update email", func(t *testing.T) {
		// Create user
		user, err := store.Create(ctx, "old@example.com", "hash")
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Update email
		err = store.UpdateEmail(ctx, user.ID, "new@example.com")
		if err != nil {
			t.Fatalf("Failed to update email: %v", err)
		}

		// Check old email doesn't work
		_, err = store.GetByEmail(ctx, "old@example.com")
		if err != core.ErrUserNotFound {
			t.Errorf("Expected ErrUserNotFound for old email, got %v", err)
		}

		// Check new email works
		found, err := store.GetByEmail(ctx, "new@example.com")
		if err != nil {
			t.Fatalf("Failed to get by new email: %v", err)
		}

		if found.ID != user.ID {
			t.Errorf("Expected user ID %s, got %s", user.ID, found.ID)
		}
	})

	t.Run("Update password", func(t *testing.T) {
		// Create user
		user, err := store.Create(ctx, "pass@example.com", "oldhash")
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Update password
		err = store.UpdatePassword(ctx, user.ID, "newhash")
		if err != nil {
			t.Fatalf("Failed to update password: %v", err)
		}

		// Get and verify
		found, err := store.GetByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("Failed to get user: %v", err)
		}

		if found.PasswordHash != "newhash" {
			t.Errorf("Expected newhash, got %s", found.PasswordHash)
		}
	})

	t.Run("Delete user", func(t *testing.T) {
		// Create user
		user, err := store.Create(ctx, "delete@example.com", "hash")
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Delete user
		err = store.Delete(ctx, user.ID)
		if err != nil {
			t.Fatalf("Failed to delete user: %v", err)
		}

		// Try to get by email
		_, err = store.GetByEmail(ctx, "delete@example.com")
		if err != core.ErrUserNotFound {
			t.Errorf("Expected ErrUserNotFound after delete, got %v", err)
		}

		// Try to get by ID
		_, err = store.GetByID(ctx, user.ID)
		if err != core.ErrUserNotFound {
			t.Errorf("Expected ErrUserNotFound after delete, got %v", err)
		}
	})
}
