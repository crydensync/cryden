package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/crydensync/cryden/cryden"
)

func main() {
	// ==================== SETUP ====================
	ctx := context.Background()

	fmt.Println("🚀 Initializing Cryden Auth Engine...")
	engine := cryden.New()

	// Optional: Set JWT secret (in production, use environment variable)
	cryden.WithJWTSecret(engine, "your-super-secret-key-change-this")

	// ==================== SIGN UP ====================
	fmt.Println("\n📝 Testing SignUp...")
	user, err := cryden.SignUp(ctx, engine, "john@example.com", "SecurePass123")
	if err != nil {
		log.Fatalf("❌ SignUp failed: %v", err)
	}
	fmt.Printf("✅ User created: ID=%s, Email=%s\n", user.ID, user.Email)

	// ==================== LOGIN ====================
	fmt.Println("\n🔑 Testing Login...")
	tokens, limit, err := cryden.Login(ctx, engine, "john@example.com", "SecurePass123")
	if err != nil {
		log.Fatalf("❌ Login failed: %v", err)
	}
	fmt.Printf("✅ Login successful!\n")
	fmt.Printf("   Access Token: %.40s...\n", tokens.AccessToken)
	fmt.Printf("   Refresh Token: %.40s...\n", tokens.RefreshToken)
	fmt.Printf("   Rate Limit Remaining: %d\n", limit.Remaining)

	// ==================== VERIFY TOKEN ====================
	fmt.Println("\n🔍 Testing Token Verification...")
	userID, err := cryden.VerifyToken(engine, tokens.AccessToken)
	if err != nil {
		log.Fatalf("❌ Token verification failed: %v", err)
	}
	fmt.Printf("✅ Token verified! User ID: %s\n", userID)

	// ==================== LIST SESSIONS ====================
	fmt.Println("\n📋 Listing Active Sessions...")
	sessions, err := cryden.ListSessions(ctx, engine, user.ID)
	if err != nil {
		log.Fatalf("❌ Failed to list sessions: %v", err)
	}
	fmt.Printf("✅ Found %d active session(s):\n", len(sessions))
	for i, s := range sessions {
		fmt.Printf("   Session %d: %s (expires: %s)\n", i+1, s.ID, s.ExpiresAt.Format(time.RFC3339))
	}

	// ==================== REFRESH TOKEN ====================
	fmt.Println("\n🔄 Testing Token Refresh...")
	newTokens, err := cryden.RefreshToken(ctx, engine, tokens.RefreshToken)
	if err != nil {
		log.Fatalf("❌ Token refresh failed: %v", err)
	}
	fmt.Printf("✅ Token refreshed!\n")
	fmt.Printf("   New Access Token: %.40s...\n", newTokens.AccessToken)
	fmt.Printf("   New Refresh Token: %.40s...\n", newTokens.RefreshToken)

	// ==================== CHANGE PASSWORD ====================
	fmt.Println("\n🔐 Testing Change Password...")
	err = cryden.ChangePassword(ctx, engine, user.ID, "SecurePass123", "NewSecurePass456")
	if err != nil {
		log.Fatalf("❌ Change password failed: %v", err)
	}
	fmt.Printf("✅ Password changed successfully!\n")

	// Test login with new password
	fmt.Println("   Testing login with new password...")
	_, _, err = cryden.Login(ctx, engine, "john@example.com", "NewSecurePass456")
	if err != nil {
		log.Fatalf("❌ Login with new password failed: %v", err)
	}
	fmt.Printf("✅ Login with new password successful!\n")

	// ==================== CHANGE EMAIL ====================
	fmt.Println("\n📧 Testing Change Email...")
	err = cryden.ChangeEmail(ctx, engine, user.ID, "john.new@example.com")
	if err != nil {
		log.Fatalf("❌ Change email failed: %v", err)
	}
	fmt.Printf("✅ Email changed to: john.new@example.com\n")

	// Verify email change
	updatedUser, err := cryden.GetUser(ctx, engine, user.ID)
	if err != nil {
		log.Fatalf("❌ Failed to get user: %v", err)
	}
	fmt.Printf("   User email is now: %s\n", updatedUser.Email)

	// ==================== LOGOUT ====================
	fmt.Println("\n🚪 Testing Logout...")

	// Login again to get new tokens after password change
	newTokens, _, err = cryden.Login(ctx, engine, "john.new@example.com", "NewSecurePass456")
	if err != nil {
		log.Fatalf("❌ Login failed: %v", err)
	}

	err = cryden.Logout(ctx, engine, newTokens.RefreshToken)
	if err != nil {
		log.Fatalf("❌ Logout failed: %v", err)
	}
	fmt.Printf("✅ Logout successful!\n")

	// Try to refresh with logged out token - should fail
	_, err = cryden.RefreshToken(ctx, engine, newTokens.RefreshToken)
	if err != nil {
		fmt.Printf("✅ Refresh with logged out token correctly failed: %v\n", err)
	}

	// ==================== LOGIN AGAIN FOR LOGOUT ALL TEST ====================
	fmt.Println("\n🔄 Logging in again for Logout All test...")
	tokens, _, err = cryden.Login(ctx, engine, "john.new@example.com", "NewSecurePass456")
	if err != nil {
		log.Fatalf("❌ Login failed: %v", err)
	}

	// Create another session by logging in again
	tokens2, _, err := cryden.Login(ctx, engine, "john.new@example.com", "NewSecurePass456")
	if err != nil {
		log.Fatalf("❌ Second login failed: %v", err)
	}
	fmt.Printf("✅ Created 2 active sessions\n")

	// ==================== LOGOUT ALL ====================
	fmt.Println("\n🚪 Testing Logout All Devices...")
	err = cryden.LogoutAll(ctx, engine, user.ID)
	if err != nil {
		log.Fatalf("❌ LogoutAll failed: %v", err)
	}
	fmt.Printf("✅ Logged out from all devices!\n")

	// Try to use old tokens - should fail
	_, err = cryden.RefreshToken(ctx, engine, tokens.RefreshToken)
	if err != nil {
		fmt.Printf("✅ First session correctly invalidated: %v\n", err)
	}
	_, err = cryden.RefreshToken(ctx, engine, tokens2.RefreshToken)
	if err != nil {
		fmt.Printf("✅ Second session correctly invalidated: %v\n", err)
	}

	// ==================== DELETE ACCOUNT ====================
	fmt.Println("\n🗑️ Testing Delete Account...")

	// Rate limiter blocks after 5 attempts per minute
	// Wait for it to reset before final login
	fmt.Println("⏱️ Rate limit active - waiting 61 seconds...")
	time.Sleep(61 * time.Second)

	// Login one last time
	_, _, err = cryden.Login(ctx, engine, "john.new@example.com", "NewSecurePass456")
	if err != nil {
		log.Fatalf("❌ Final login failed: %v", err)
	}

	err = cryden.DeleteAccount(ctx, engine, user.ID)
	if err != nil {
		log.Fatalf("❌ Delete account failed: %v", err)
	}
	fmt.Printf("✅ Account deleted successfully!\n")

	// Try to login with deleted account - should fail
	_, _, err = cryden.Login(ctx, engine, "john.new@example.com", "NewSecurePass456")
	if err != nil {
		fmt.Printf("✅ Login with deleted account correctly failed: %v\n", err)
	}

	fmt.Println("\n🎉 All Cryden features tested successfully!")
}
