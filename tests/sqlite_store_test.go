package tests

import (
	"context"
	"os"
	"testing"

	"github.com/raymondproguy/credensync/core"
	"github.com/raymondproguy/credensync/stores/sqlite"
)

func TestSQLiteUserStore(t *testing.T) {
	// Use temporary database file
	dbPath := "test_users.db"
	defer os.Remove(dbPath)

	store, err := sqlite.NewUserStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	t.Run("Create and Get user", func(t *testing.T) {
		user, err := store.Create(ctx, "test@example.com", "hash123")
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		if user.Email != "test@example.com" {
			t.Errorf("Expected email test@example.com, got %s", user.Email)
		}

		// Get by email
		found, err := store.GetByEmail(ctx, "test@example.com")
		if err != nil {
			t.Fatalf("Failed to get by email: %v", err)
		}
		if found.ID != user.ID {
			t.Errorf("Expected ID %s, got %s", user.ID, found.ID)
		}
	})

	t.Run("Duplicate email", func(t *testing.T) {
		_, err := store.Create(ctx, "duplicate@example.com", "hash")
		if err != nil {
			t.Fatalf("First create failed: %v", err)
		}

		_, err = store.Create(ctx, "duplicate@example.com", "hash")
		if err != core.ErrUserExists {
			t.Errorf("Expected ErrUserExists, got %v", err)
		}
	})

}
