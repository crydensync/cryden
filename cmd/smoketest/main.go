package main

import (
	"context"
	"fmt"
	"os"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/store/memory"
)

func check(label string, err error) {
	if err != nil {
		fmt.Printf("FAIL %s: %v\n", label, err)
		os.Exit(1)
	}
	fmt.Printf("OK   %s\n", label)
}

func main() {
	ctx := context.Background()

	engine, err := cryden.New(cryden.Config{
		JWTSecret: "test-secret-do-not-use-in-prod",
		Users:     memory.NewUserStore(),
		Sessions:  memory.NewSessionStore(),
		Audit:     memory.NewAuditStore(),
	})
	check("engine construction", err)

	// SignUp
	user, err := cryden.SignUp(ctx, engine, "alice@example.com", "SecurePass123!", "1.2.3.4")
	check("signup", err)
	fmt.Printf("     user id: %s\n", user.ID)

	// SignUp duplicate should fail
	_, err = cryden.SignUp(ctx, engine, "alice@example.com", "SecurePass123!", "1.2.3.4")
	if err == nil {
		fmt.Println("FAIL duplicate signup: expected error, got nil")
		os.Exit(1)
	}
	fmt.Println("OK   duplicate signup correctly rejected")

	// Login
	tokens, err := cryden.Login(ctx, engine, "alice@example.com", "SecurePass123!", "1.2.3.4", "test-agent")
	check("login", err)
	fmt.Printf("     access token len: %d, refresh token len: %d\n", len(tokens.AccessToken), len(tokens.RefreshToken))

	// Login wrong password should fail generically
	_, err = cryden.Login(ctx, engine, "alice@example.com", "WrongPassword", "1.2.3.4", "test-agent")
	if err == nil {
		fmt.Println("FAIL wrong password: expected error, got nil")
		os.Exit(1)
	}
	fmt.Println("OK   wrong password correctly rejected")

	// VerifyToken
	userID, err := cryden.VerifyToken(engine, tokens.AccessToken)
	check("verify token", err)
	if userID != user.ID {
		fmt.Printf("FAIL verify token: expected %s, got %s\n", user.ID, userID)
		os.Exit(1)
	}
	fmt.Println("OK   verified user id matches")

	// RefreshToken (rotation)
	newTokens, err := cryden.RefreshToken(ctx, engine, tokens.RefreshToken)
	check("refresh rotation", err)
	if newTokens.RefreshToken == tokens.RefreshToken {
		fmt.Println("FAIL refresh rotation: token did not change")
		os.Exit(1)
	}
	fmt.Println("OK   refresh token rotated to a new value")

	// Reuse the OLD (now-revoked) refresh token — should trigger reuse detection
	_, err = cryden.RefreshToken(ctx, engine, tokens.RefreshToken)
	if err == nil {
		fmt.Println("FAIL reuse detection: expected error, got nil")
		os.Exit(1)
	}
	fmt.Printf("OK   reuse detection triggered: %v\n", err)

	// Because reuse revokes the whole family, the NEW token should also now be dead
	_, err = cryden.RefreshToken(ctx, engine, newTokens.RefreshToken)
	if err == nil {
		fmt.Println("FAIL family revocation: new token should also be dead after reuse detected")
		os.Exit(1)
	}
	fmt.Println("OK   entire session family correctly revoked after reuse detection")

	// List sessions (should be empty now — the only session was just killed by reuse detection)
	sessions, err := cryden.ListSessions(ctx, engine, user.ID)
	check("list sessions", err)
	fmt.Printf("     active sessions: %d (expected 0)\n", len(sessions))

	// Fresh login, then logout
	tokens2, err := cryden.Login(ctx, engine, "alice@example.com", "SecurePass123!", "1.2.3.4", "test-agent")
	check("second login", err)

	sessionsBeforeLogout, err := cryden.ListSessions(ctx, engine, user.ID)
	check("list sessions before logout", err)
	if len(sessionsBeforeLogout) != 1 {
		fmt.Printf("FAIL expected 1 active session, got %d\n", len(sessionsBeforeLogout))
		os.Exit(1)
	}
	sid := sessionsBeforeLogout[0].ID

	err = cryden.Logout(ctx, engine, sid, user.ID)
	check("logout", err)

	sessionsAfterLogout, err := cryden.ListSessions(ctx, engine, user.ID)
	check("list sessions after logout", err)
	if len(sessionsAfterLogout) != 0 {
		fmt.Printf("FAIL expected 0 active sessions after logout, got %d\n", len(sessionsAfterLogout))
		os.Exit(1)
	}
	fmt.Println("OK   logout correctly revoked the session")

	_ = tokens2

	fmt.Println("\nALL CHECKS PASSED")
}