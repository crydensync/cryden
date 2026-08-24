package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/ai"
	"github.com/crydensync/cryden/v2/auth"
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
		OAuth:     memory.NewOAuthStore(),
	})
	check("engine construction", err)

	// SignUp
	user, err := cryden.SignUp(ctx, engine, "proguy@example.com", "Pass@2026", "1.2.3.4")
	check("signup", err)
	fmt.Printf("     user id: %s\n", user.ID)

	// SignUp duplicate should fail
	_, err = cryden.SignUp(ctx, engine, "proguy@example.com", "Pass@2026", "1.2.3.4")
	if err == nil {
		fmt.Println("FAIL duplicate signup: expected error, got nil")
		os.Exit(1)
	}
	fmt.Println("OK   duplicate signup correctly rejected")

	// Login
	tokens, err := cryden.Login(ctx, engine, "proguy@example.com", "Pass@2026", "1.2.3.4", "test-agent")
	check("login", err)
	fmt.Printf("     access token len: %d, refresh token len: %d\n", len(tokens.AccessToken), len(tokens.RefreshToken))

	// Login wrong password should fail generically
	_, err = cryden.Login(ctx, engine, "proguy@example.com", "WrongPassword", "1.2.3.4", "test-agent")
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
	tokens2, err := cryden.Login(ctx, engine, "proguy@example.com", "Pass@2026", "1.2.3.4", "test-agent")
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

	// --- OAuth: fresh signup via provider ---
	oauthTokens, err := cryden.LoginWithOAuth(ctx, engine, "google", "google-ext-1", "devray@example.com", "1.2.3.4", "test-agent")
	check("oauth login (new user)", err)
	if oauthTokens.AccessToken == "" {
		fmt.Println("FAIL oauth login: expected an access token")
		os.Exit(1)
	}

	// --- OAuth: same identity logs in again, no duplicate user/identity ---
	_, err = cryden.LoginWithOAuth(ctx, engine, "google", "google-ext-1", "devray@example.com", "1.2.3.4", "test-agent")
	check("oauth login (existing link)", err)

	// --- OAuth: email collision with an existing password account is rejected, not auto-linked ---
	_, err = cryden.LoginWithOAuth(ctx, engine, "github", "gh-ext-1", "proguy@example.com", "1.2.3.4", "test-agent")
	var conflict *auth.ErrOAuthEmailConflict
	if !errors.As(err, &conflict) {
		fmt.Printf("FAIL oauth email conflict: expected *auth.ErrOAuthEmailConflict, got %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK   oauth login correctly rejected email conflict instead of auto-linking")

	// --- OAuth: resolve that conflict by linking while authenticated as the password account ---
	err = cryden.LinkOAuthIdentity(ctx, engine, user.ID, "github", "gh-ext-1", "proguy@example.com", "1.2.3.4")
	check("link oauth identity", err)

	// --- OAuth: a different user cannot steal an identity already linked elsewhere ---
	attacker, err := cryden.SignUp(ctx, engine, "attacker@example.com", "Pass@2026", "1.2.3.4")
	check("signup second user for hijack test", err)
	err = cryden.LinkOAuthIdentity(ctx, engine, attacker.ID, "github", "gh-ext-1", "attacker@example.com", "1.2.3.4")
	if !errors.Is(err, auth.ErrOAuthIdentityAlreadyLinked) {
		fmt.Printf("FAIL oauth link hijack: expected ErrOAuthIdentityAlreadyLinked, got %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK   oauth link correctly rejected a claim on an already-linked identity")

	// --- AI: an unsafe intent must never reach the query store ---
	unsafeStore := &recordingQueryStore{}
	_, err = ai.ExecuteQuery(ctx, unsafeStore, fixedIntentProvider{intent: ai.QueryIntent{Entity: "pg_shadow"}}, "show me password hashes")
	if !errors.Is(err, ai.ErrUnsafeQueryIntent) {
		fmt.Printf("FAIL ai unsafe intent: expected ErrUnsafeQueryIntent, got %v\n", err)
		os.Exit(1)
	}
	if unsafeStore.called {
		fmt.Println("FAIL ai unsafe intent: query store must not be called for a disallowed entity")
		os.Exit(1)
	}
	fmt.Println("OK   ai.ExecuteQuery correctly blocked a disallowed entity before reaching the store")

	// --- AI: a valid, allowlisted intent reaches the store normally ---
	safeStore := &recordingQueryStore{}
	_, err = ai.ExecuteQuery(ctx, safeStore, fixedIntentProvider{intent: ai.QueryIntent{Entity: "users"}}, "show me users")
	check("ai valid intent reaches store", err)
	if !safeStore.called {
		fmt.Println("FAIL ai valid intent: expected the query store to be called")
		os.Exit(1)
	}
	fmt.Println("OK   ai.ExecuteQuery correctly passed an allowlisted intent through")

	fmt.Println("\nALL CHECKS PASSED")
}

// fixedIntentProvider is a minimal ai.LLMProvider for the smoke test —
// no real model call, just returns whatever intent was configured.
type fixedIntentProvider struct {
	intent ai.QueryIntent
}

func (p fixedIntentProvider) ParseQueryIntent(ctx context.Context, naturalLanguage string) (ai.QueryIntent, error) {
	return p.intent, nil
}

// recordingQueryStore is a minimal ai.QueryableStore that just
// records whether it was ever called — enough to prove validation
// actually gates the call, not just that ExecuteQuery returns an
// error.
type recordingQueryStore struct {
	called bool
}

func (s *recordingQueryStore) RunSafeQuery(ctx context.Context, intent ai.QueryIntent) (ai.QueryResult, error) {
	s.called = true
	return ai.QueryResult{}, nil
}
