package tests

import (
	"context"
	"os"
	"testing"

	"github.com/crydensync/cryden/internal/core"
	"github.com/crydensync/cryden/internal/stores/memory"
	"github.com/crydensync/cryden/internal/stores/mongodb"
	"github.com/crydensync/cryden/internal/stores/postgres"
	"github.com/crydensync/cryden/internal/stores/sqlite"
)

// TestUserStore runs the same tests for ALL implementations
func TestUserStore(t *testing.T) {
	// Run tests for each store implementation
	t.Run("Memory", func(t *testing.T) {
		store := memory.NewUserStore()
		defer store.Close()
		testUserStore(t, store)
	})

	t.Run("SQLite", func(t *testing.T) {
		dbPath := "test_sqlite.db"
		defer os.Remove(dbPath)

		store, err := sqlite.NewUserStore(dbPath)
		if err != nil {
			t.Fatalf("Failed to create SQLite store: %v", err)
		}
		defer store.Close()

		testUserStore(t, store)
	})

	t.Run("PostgreSQL", func(t *testing.T) {
		// Use environment variable for connection string
		connStr := os.Getenv("TEST_POSTGRES_URI")
		if connStr == "" {
			t.Skip("Skipping PostgreSQL test: TEST_POSTGRES_URI not set")
		}

		store, err := postgres.NewUserStore(connStr)
		if err != nil {
			t.Fatalf("Failed to create PostgreSQL store: %v", err)
		}
		defer store.Close()

		testUserStore(t, store)
	})

	t.Run("MongoDB", func(t *testing.T) {
		// Use environment variable for connection string
		uri := os.Getenv("TEST_MONGODB_URI")
		if uri == "" {
			t.Skip("Skipping MongoDB test: TEST_MONGODB_URI not set")
		}

		store, err := mongodb.NewUserStore(uri, "test_db")
		if err != nil {
			t.Fatalf("Failed to create MongoDB store: %v", err)
		}
		defer store.Close()

		testUserStore(t, store)
	})
}

// testUserStore contains the actual tests
func testUserStore(t *testing.T, store core.UserStore) {
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

		if user.ID == "" {
			t.Error("Expected user ID to be set")
		}

		// Get by email
		found, err := store.GetByEmail(ctx, "test@example.com")
		if err != nil {
			t.Fatalf("Failed to get by email: %v", err)
		}

		if found.ID != user.ID {
			t.Errorf("Expected ID %s, got %s", user.ID, found.ID)
		}

		// Get by ID
		found, err = store.GetByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("Failed to get by ID: %v", err)
		}

		if found.Email != user.Email {
			t.Errorf("Expected email %s, got %s", user.Email, found.Email)
		}
	})

	t.Run("Duplicate email", func(t *testing.T) {
		// First creation
		_, err := store.Create(ctx, "duplicate@example.com", "hash1")
		if err != nil {
			t.Fatalf("First create failed: %v", err)
		}

		// Second creation with same email
		_, err = store.Create(ctx, "duplicate@example.com", "hash2")
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

		// Try old email
		_, err = store.GetByEmail(ctx, "old@example.com")
		if err != core.ErrUserNotFound {
			t.Errorf("Expected ErrUserNotFound for old email, got %v", err)
		}

		// Try new email
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
	})
}
