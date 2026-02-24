// tests/engine_test.go
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/raymondproguy/credensync/core"
	"github.com/raymondproguy/credensync/stores/memory"
)

func TestSignUp(t *testing.T) {
	// Setup
	userStore := memory.NewUserStore()
	sessionStore := memory.NewSessionStore()
	engine := core.New(userStore, sessionStore)
	ctx := context.Background()

	t.Run("valid signup", func(t *testing.T) {
		user, err := engine.SignUp(ctx, "test@example.com", "Password123")

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		if user == nil {
			t.Fatal("Expected user, got nil")
		}

		if user.Email != "test@example.com" {
			t.Errorf("Expected email test@example.com, got %s", user.Email)
		}

		if user.ID == "" {
			t.Error("Expected user ID to be set")
		}
	})

	t.Run("duplicate email", func(t *testing.T) {
		// First signup
		_, err := engine.SignUp(ctx, "duplicate@example.com", "Password123")
		if err != nil {
			t.Fatalf("First signup failed: %v", err)
		}

		// Second signup with same email
		_, err = engine.SignUp(ctx, "duplicate@example.com", "Password123")
		if err != core.ErrUserExists {
			t.Errorf("Expected ErrUserExists, got %v", err)
		}
	})

	t.Run("invalid email", func(t *testing.T) {
		testCases := []struct {
			email    string
			password string
			wantErr  error
		}{
			{"", "Password123", core.ErrInvalidEmail},
			{"notanemail", "Password123", core.ErrInvalidEmail},
			{"@domain.com", "Password123", core.ErrInvalidEmail},
			{"user@", "Password123", core.ErrInvalidEmail},
			{"user@domain", "Password123", core.ErrInvalidEmail},
		}

		for _, tc := range testCases {
			_, err := engine.SignUp(ctx, tc.email, tc.password)
			if err == nil {
				t.Errorf("Expected error for email %q, got nil", tc.email)
				continue
			}

			// Check if it's a ValidationError
			if verr, ok := err.(*core.ValidationError); ok {
				if verr.Field != "email" {
					t.Errorf("Expected field 'email', got %q", verr.Field)
				}
			} else {
				t.Errorf("Expected ValidationError, got %T", err)
			}
		}
	})

	t.Run("invalid password", func(t *testing.T) {
		testCases := []struct {
			password string
			wantErr  error
		}{
			{"short", core.ErrPasswordToShort},
			{"onlylowercase", core.ErrPasswordNoUpper},
			{"ONLYUPPERCASE", core.ErrPasswordNoLower},
			{"NoNumbers", core.ErrPasswordNoNumber},
		}

		for _, tc := range testCases {
			_, err := engine.SignUp(ctx, "test@example.com", tc.password)
			if err == nil {
				t.Errorf("Expected error for password %q, got nil", tc.password)
				continue
			}

			if verr, ok := err.(*core.ValidationError); ok {
				if verr.Field != "password" {
					t.Errorf("Expected field 'password', got %q", verr.Field)
				}
			}
		}
	})
}

func TestLogin(t *testing.T) {
	// Setup
	userStore := memory.NewUserStore()
	sessionStore := memory.NewSessionStore()
	engine := core.New(userStore, sessionStore)
	ctx := context.Background()

	// Create a test user
	_, err := engine.SignUp(ctx, "login@example.com", "Password123")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	t.Run("valid login", func(t *testing.T) {
		tokens, _, err := engine.Login(ctx, "login@example.com", "Password123")

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		if tokens == nil {
			t.Fatal("Expected tokens, got nil")
		}

		if tokens.AccessToken == "" {
			t.Error("Expected access token, got empty")
		}

		if tokens.RefreshToken == "" {
			t.Error("Expected refresh token, got empty")
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		_, _, err := engine.Login(ctx, "login@example.com", "wrongpassword")

		if err != core.ErrInvalidCredentials {
			t.Errorf("Expected ErrInvalidCredentials, got %v", err)
		}
	})

	t.Run("nonexistent user", func(t *testing.T) {
		_, _, err := engine.Login(ctx, "nonexistent@example.com", "Password123")

		if err != core.ErrInvalidCredentials {
			t.Errorf("Expected ErrInvalidCredentials, got %v", err)
		}
	})
}

func TestLoginRateLimiting(t *testing.T) {
	// Setup
	userStore := memory.NewUserStore()
	sessionStore := memory.NewSessionStore()
	ctx := context.Background()

	// Create engine with strict rate limit (2 per minute)
	engine := core.New(userStore, sessionStore)
	limiter := core.NewMemoryRateLimiter(2, time.Minute)
	engine.WithRateLimiter(limiter)

	// Create a test user
	_, err := engine.SignUp(ctx, "ratelimit@example.com", "Password123")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	t.Run("first two attempts allowed", func(t *testing.T) {
		// First attempt
		_, result, err := engine.Login(ctx, "ratelimit@example.com", "Password123")
		if err != nil {
			t.Errorf("First login failed: %v", err)
		}
		if result.Remaining != 1 {
			t.Errorf("Expected remaining 1, got %d", result.Remaining)
		}

		// Second attempt
		_, result, err = engine.Login(ctx, "ratelimit@example.com", "Password123")
		if err != nil {
			t.Errorf("Second login failed: %v", err)
		}
		if result.Remaining != 0 {
			t.Errorf("Expected remaining 0, got %d", result.Remaining)
		}
	})

	t.Run("third attempt blocked", func(t *testing.T) {
		_, result, err := engine.Login(ctx, "ratelimit@example.com", "Password123")
		if err != core.ErrTooManyAttempts {
			t.Errorf("Expected ErrTooManyAttempts, got %v", err)
		}
		if result.Allowed {
			t.Error("Expected not allowed")
		}
	})
}
