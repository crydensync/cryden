package tests

import (
	"github.com/crydensync/cryden/internal/core"
	"testing"
	"time"
)

func TestJWTTokens(t *testing.T) {
	engine := core.New(nil, nil)
	engine.WithJWTSecret("test-secret")

	t.Run("generate and verify token", func(t *testing.T) {
		// Since generateTokens needs a session store, we'll test the JWT part separately
		userID := "user_123"

		// Manually create claims
		claims := core.Claims{
			UserID: userID,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
				Issuer:    "cryden",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte("test-secret"))
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		// Verify
		verifiedClaims, err := engine.VerifyToken(tokenString)
		if err != nil {
			t.Fatalf("Failed to verify token: %v", err)
		}

		if verifiedClaims.UserID != userID {
			t.Errorf("Expected userID %s, got %s", userID, verifiedClaims.UserID)
		}
	})
}
