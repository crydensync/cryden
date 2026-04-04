// tests/engine_test.go
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/crydensync/cryden/internal/core"
	"github.com/crydensync/cryden/internal/stores/memory"
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
			{"short", core.ErrPasswordTooShort},
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

func TestLogout(t *testing.T) {
	userStore := memory.NewUserStore()
	sessionStore := memory.NewSessionStore()
	engine := core.New(userStore, sessionStore)
	ctx := context.Background()

	engine.SignUp(ctx, "logout@example.com", "Password123")
	tokens, _, _ := engine.Login(ctx, "logout@example.com", "Password123")

	t.Run("valid logout", func(t *testing.T) {
		err := engine.Logout(ctx, tokens.RefreshToken)
		if err != nil {
			t.Errorf("Logout failed: %v", err)
		}

		_, err = engine.GetSessionStore().GetByRefreshToken(ctx, tokens.RefreshToken)
		if err != core.ErrSessionNotFound {
			t.Errorf("Expected session not found, got %v", err)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		err := engine.Logout(ctx, "invalid")
		if err != core.ErrInvalidToken {
			t.Errorf("Expected ErrInvalidToken, got %v", err)
		}
	})
}

func TestLogoutAll(t *testing.T) {
	userStore := memory.NewUserStore()
	sessionStore := memory.NewSessionStore()
	engine := core.New(userStore, sessionStore)
	ctx := context.Background()

	engine.SignUp(ctx, "logoutall@example.com", "Password123")

	// Create multiple sessions
	tokens1, _, _ := engine.Login(ctx, "logoutall@example.com", "Password123")
	tokens2, _, _ := engine.Login(ctx, "logoutall@example.com", "Password123")
	tokens3, _, _ := engine.Login(ctx, "logoutall@example.com", "Password123")

	t.Run("logout all devices", func(t *testing.T) {
		user, _ := engine.GetUserStore().GetByEmail(ctx, "logoutall@example.com")
		err := engine.LogoutAll(ctx, user.ID)
		if err != nil {
			t.Errorf("LogoutAll failed: %v", err)
		}

		// All sessions should be gone
		_, err = engine.GetSessionStore().GetByRefreshToken(ctx, tokens1.RefreshToken)
		if err != core.ErrSessionNotFound {
			t.Error("First session still exists")
		}
		_, err = engine.GetSessionStore().GetByRefreshToken(ctx, tokens2.RefreshToken)
		if err != core.ErrSessionNotFound {
			t.Error("Second session still exists")
		}
		_, err = engine.GetSessionStore().GetByRefreshToken(ctx, tokens3.RefreshToken)
		if err != core.ErrSessionNotFound {
			t.Error("Third session still exists")
		}
	})
}

func TestChangePassword(t *testing.T) {
	userStore := memory.NewUserStore()
	sessionStore := memory.NewSessionStore()
	engine := core.New(userStore, sessionStore)
	ctx := context.Background()

	// Create user and login
	engine.SignUp(ctx, "pass@example.com", "OldPass123")
	user, _ := engine.GetUserStore().GetByEmail(ctx, "pass@example.com")
	tokens, _, _ := engine.Login(ctx, "pass@example.com", "OldPass123")

	t.Run("successful password change", func(t *testing.T) {
		err := engine.ChangePassword(ctx, user.ID, "OldPass123", "NewPass456")
		if err != nil {
			t.Errorf("ChangePassword failed: %v", err)
		}

		// Old password should not work
		_, _, err = engine.Login(ctx, "pass@example.com", "OldPass123")
		if err != core.ErrInvalidCredentials {
			t.Error("Old password still works")
		}

		// New password should work
		_, _, err = engine.Login(ctx, "pass@example.com", "NewPass456")
		if err != nil {
			t.Error("New password doesn't work")
		}

		// Old session should be revoked
		_, err = engine.GetSessionStore().GetByRefreshToken(ctx, tokens.RefreshToken)
		if err != core.ErrSessionNotFound {
			t.Error("Old session still exists")
		}
	})

	t.Run("wrong old password", func(t *testing.T) {
		err := engine.ChangePassword(ctx, user.ID, "WrongPass", "NewPass456")
		if err != core.ErrInvalidCredentials {
			t.Errorf("Expected ErrInvalidCredentials, got %v", err)
		}
	})

	t.Run("invalid new password", func(t *testing.T) {
		err := engine.ChangePassword(ctx, user.ID, "NewPass456", "short")
		if err == nil {
			t.Error("Expected validation error, got nil")
		}
	})
}

func TestChangeEmail(t *testing.T) {
	userStore := memory.NewUserStore()
	sessionStore := memory.NewSessionStore()
	engine := core.New(userStore, sessionStore)
	ctx := context.Background()

	// Create user
	engine.SignUp(ctx, "old@example.com", "Password123")
	user, _ := engine.GetUserStore().GetByEmail(ctx, "old@example.com")

	t.Run("successful email change", func(t *testing.T) {
		err := engine.ChangeEmail(ctx, user.ID, "new@example.com")
		if err != nil {
			t.Errorf("ChangeEmail failed: %v", err)
		}

		// Old email should not work
		_, err = engine.GetUserStore().GetByEmail(ctx, "old@example.com")
		if err != core.ErrUserNotFound {
			t.Error("Old email still exists")
		}

		// New email should work
		found, err := engine.GetUserStore().GetByEmail(ctx, "new@example.com")
		if err != nil {
			t.Error("New email not found")
		}
		if found.ID != user.ID {
			t.Error("Wrong user returned")
		}
	})

	t.Run("duplicate email", func(t *testing.T) {
		engine.SignUp(ctx, "duplicate@example.com", "Password123")
		duplicate, _ := engine.GetUserStore().GetByEmail(ctx, "duplicate@example.com")

		err := engine.ChangeEmail(ctx, duplicate.ID, "new@example.com")
		if err != core.ErrUserExists {
			t.Errorf("Expected ErrUserExists, got %v", err)
		}
	})

	t.Run("invalid email", func(t *testing.T) {
		err := engine.ChangeEmail(ctx, user.ID, "notanemail")
		if err == nil {
			t.Error("Expected validation error, got nil")
		}
	})
}

func TestDeleteAccount(t *testing.T) {
	userStore := memory.NewUserStore()
	sessionStore := memory.NewSessionStore()
	engine := core.New(userStore, sessionStore)
	ctx := context.Background()

	// Create user and sessions
	engine.SignUp(ctx, "delete@example.com", "Password123")
	user, _ := engine.GetUserStore().GetByEmail(ctx, "delete@example.com")

	// Create multiple sessions
	tokens1, _, _ := engine.Login(ctx, "delete@example.com", "Password123")
	tokens2, _, _ := engine.Login(ctx, "delete@example.com", "Password123")

	t.Run("delete account", func(t *testing.T) {
		err := engine.DeleteAccount(ctx, user.ID)
		if err != nil {
			t.Errorf("DeleteAccount failed: %v", err)
		}

		// User should be gone
		_, err = engine.GetUserStore().GetByEmail(ctx, "delete@example.com")
		if err != core.ErrUserNotFound {
			t.Error("User still exists")
		}

		// Sessions should be gone
		_, err = engine.GetSessionStore().GetByRefreshToken(ctx, tokens1.RefreshToken)
		if err != core.ErrSessionNotFound {
			t.Error("First session still exists")
		}
		_, err = engine.GetSessionStore().GetByRefreshToken(ctx, tokens2.RefreshToken)
		if err != core.ErrSessionNotFound {
			t.Error("Second session still exists")
		}
	})

	t.Run("delete nonexistent user", func(t *testing.T) {
		err := engine.DeleteAccount(ctx, "nonexistent")
		if err != core.ErrUserNotFound {
			t.Errorf("Expected ErrUserNotFound, got %v", err)
		}
	})
}

func TestRefreshToken(t *testing.T) {
	userStore := memory.NewUserStore()
	sessionStore := memory.NewSessionStore()
	engine := core.New(userStore, sessionStore)
	ctx := context.Background()

	// Create user and login
	engine.SignUp(ctx, "refresh@example.com", "Password123")
	tokens, _, _ := engine.Login(ctx, "refresh@example.com", "Password123")

	t.Run("successful refresh", func(t *testing.T) {
		newTokens, err := engine.RefreshToken(ctx, tokens.RefreshToken)
		if err != nil {
			t.Errorf("Refresh failed: %v", err)
		}

		if newTokens.AccessToken == tokens.AccessToken {
			t.Error("Access token should be new")
		}
		if newTokens.RefreshToken == tokens.RefreshToken {
			t.Error("Refresh token should be new")
		}

		// Old refresh token should be revoked
		_, err = engine.GetSessionStore().GetByRefreshToken(ctx, tokens.RefreshToken)
		if err != core.ErrSessionNotFound {
			t.Error("Old session still exists")
		}

		// New refresh token should work
		_, err = engine.GetSessionByRefreshToken(ctx, newTokens.RefreshToken)
		if err != nil {
			t.Error("New session not found")
		}
	})

	t.Run("refresh with invalid token", func(t *testing.T) {
		_, err := engine.RefreshToken(ctx, "invalid")
		if err != core.ErrInvalidToken {
			t.Errorf("Expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("refresh with already used token", func(t *testing.T) {
		// First refresh - works
		newTokens, _ := engine.RefreshToken(ctx, tokens.RefreshToken)

		// Second refresh with same token - should fail (already revoked)
		_, err := engine.RefreshToken(ctx, tokens.RefreshToken)
		if err != core.ErrInvalidToken {
			t.Errorf("Expected ErrInvalidToken for used token, got %v", err)
		}
    
		if newTokens != nil {
		// New token should still work
		_, err = engine.RefreshToken(ctx, newTokens.RefreshToken)
		if err != nil {
			t.Error("New token should work")
		}
	}
	})
}
