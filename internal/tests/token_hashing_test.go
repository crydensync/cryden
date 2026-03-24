package tests

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "testing"
    "time"

    "github.com/crydensync/cryden/internal/core"
    "github.com/crydensync/cryden/internal/stores/memory"
    "github.com/crydensync/cryden/internal/token"
)

func TestTokenHashing(t *testing.T) {
    t.Run("generate and verify refresh token", func(t *testing.T) {
        hasher := core.NewBcryptHasher(10)
        svc := token.NewService(hasher)

        // Generate token
        bundle, err := svc.GenerateRefreshToken()
        if err != nil {
            t.Fatalf("Failed to generate token: %v", err)
        }

        // Check all parts present
        if bundle.PlainText == "" {
            t.Error("Plain text token empty")
        }
        if bundle.LookupHash == "" {
            t.Error("Lookup hash empty")
        }
        if bundle.StorageHash == "" {
            t.Error("Storage hash empty")
        }

        // Verify lookup hash is correct SHA256
        expectedLookup := sha256.Sum256([]byte(bundle.PlainText))
        if bundle.LookupHash != hex.EncodeToString(expectedLookup[:]) {
            t.Error("Lookup hash doesn't match plain token")
        }

        // Verify storage hash works
        if err := svc.VerifyRefreshToken(bundle.PlainText, bundle.StorageHash); err != nil {
            t.Error("Storage hash failed to verify plain token")
        }

        // Wrong token should fail
        if err := svc.VerifyRefreshToken("wrong-token", bundle.StorageHash); err == nil {
            t.Error("Verification should fail for wrong token")
        }
    })
}

func TestSessionStoreWithHashedTokens(t *testing.T) {
    userStore := memory.NewUserStore()
    sessionStore := memory.NewSessionStore()
    hasher := core.NewBcryptHasher(10)
    tokenSvc := token.NewService(hasher)
    
    ctx := context.Background()

    // Create a test user
    user, err := userStore.Create(ctx, "test@example.com", "password-hash")
    if err != nil {
        t.Fatalf("Failed to create user: %v", err)
    }

    t.Run("create and retrieve session", func(t *testing.T) {
        // Generate token
        bundle, err := tokenSvc.GenerateRefreshToken()
        if err != nil {
            t.Fatalf("Failed to generate token: %v", err)
        }

        // Create session
        session, err := sessionStore.Create(ctx, user.ID, bundle.StorageHash, bundle.LookupHash)
        if err != nil {
            t.Fatalf("Failed to create session: %v", err)
        }

        // Retrieve by lookup hash
        found, err := sessionStore.GetByRefreshToken(ctx, bundle.LookupHash)
        if err != nil {
            t.Fatalf("Failed to get session: %v", err)
        }

        // Verify token
        if err := tokenSvc.VerifyRefreshToken(bundle.PlainText, found.RefreshToken); err != nil {
            t.Error("Failed to verify token")
        }

        // Wrong lookup hash should fail
        _, err = sessionStore.GetByRefreshToken(ctx, "wrong-hash")
        if err != core.ErrSessionNotFound {
            t.Error("Should not find session with wrong lookup hash")
        }
    })

    t.Run("list sessions doesn't expose lookup hash", func(t *testing.T) {
        // Create a session
        bundle, _ := tokenSvc.GenerateRefreshToken()
        sessionStore.Create(ctx, user.ID, bundle.StorageHash, bundle.LookupHash)

        // List sessions
        sessions, err := sessionStore.ListForUser(ctx, user.ID)
        if err != nil {
            t.Fatalf("Failed to list sessions: %v", err)
        }

        // Check lookup hash is empty in list response
        for _, s := range sessions {
            if s.LookupHash != "" {
                t.Error("Lookup hash should not be exposed in ListForUser")
            }
        }
    })

    t.Run("revoke session", func(t *testing.T) {
        // Create session
        bundle, _ := tokenSvc.GenerateRefreshToken()
        session, err := sessionStore.Create(ctx, user.ID, bundle.StorageHash, bundle.LookupHash)
        if err != nil {
            t.Fatalf("Failed to create session: %v", err)
        }

        // Revoke it
        err = sessionStore.Revoke(ctx, session.ID)
        if err != nil {
            t.Fatalf("Failed to revoke session: %v", err)
        }

        // Should not be findable
        _, err = sessionStore.GetByRefreshToken(ctx, bundle.LookupHash)
        if err != core.ErrSessionNotFound {
            t.Error("Session still exists after revoke")
        }
    })
}

func TestFullLoginFlowWithHashedTokens(t *testing.T) {
    userStore := memory.NewUserStore()
    sessionStore := memory.NewSessionStore()
    
    // Create engine
    engine := core.New(userStore, sessionStore)
    ctx := context.Background()

    // Sign up
    user, err := engine.SignUp(ctx, "flow@example.com", "Password123")
    if err != nil {
        t.Fatalf("SignUp failed: %v", err)
    }

    t.Run("login stores hashed token", func(t *testing.T) {
        // Login
        tokens, _, err := engine.Login(ctx, "flow@example.com", "Password123")
        if err != nil {
            t.Fatalf("Login failed: %v", err)
        }

        // Try to find session by looking up with SHA256
        sha := sha256.Sum256([]byte(tokens.RefreshToken))
        lookupHash := hex.EncodeToString(sha[:])

        session, err := sessionStore.GetByRefreshToken(ctx, lookupHash)
        if err != nil {
            t.Fatalf("Failed to find session: %v", err)
        }

        // Verify user ID matches
        if session.UserID != user.ID {
            t.Errorf("Expected user ID %s, got %s", user.ID, session.UserID)
        }

        // Verify token in DB is not plain text
        if session.RefreshToken == tokens.RefreshToken {
            t.Error("Refresh token stored in plain text!")
        }
    })

    t.Run("refresh token rotation", func(t *testing.T) {
        // Login
        tokens, _, err := engine.Login(ctx, "flow@example.com", "Password123")
        if err != nil {
            t.Fatalf("Login failed: %v", err)
        }

        oldPlainToken := tokens.RefreshToken
        oldLookup := sha256.Sum256([]byte(oldPlainToken))
        oldLookupHash := hex.EncodeToString(oldLookup[:])

        // Refresh
        newTokens, err := engine.RefreshToken(ctx, oldPlainToken)
        if err != nil {
            t.Fatalf("Refresh failed: %v", err)
        }

        // Old token should be invalid
        _, err = sessionStore.GetByRefreshToken(ctx, oldLookupHash)
        if err != core.ErrSessionNotFound {
            t.Error("Old token still valid after refresh")
        }

        // New token should work
        newLookup := sha256.Sum256([]byte(newTokens.RefreshToken))
        newLookupHash := hex.EncodeToString(newLookup[:])
        
        session, err := sessionStore.GetByRefreshToken(ctx, newLookupHash)
        if err != nil {
            t.Error("New token not working")
        }

        // Verify new token hash matches
        if err := engine.hasher.Compare(newTokens.RefreshToken, session.RefreshToken); err != nil {
            t.Error("New token verification failed")
        }
    })
}
