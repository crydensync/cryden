package token

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTIssuer_IssueAndVerify(t *testing.T) {
	iss, err := NewJWTIssuer("test-secret", time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tok, err := iss.Issue("user-123")
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	userID, err := iss.Verify(tok)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if userID != "user-123" {
		t.Errorf("expected user-123, got %s", userID)
	}
}

func TestJWTIssuer_RejectsExpiredToken(t *testing.T) {
	iss, _ := NewJWTIssuer("test-secret", 1*time.Millisecond)
	tok, _ := iss.Issue("user-123")

	time.Sleep(10 * time.Millisecond)

	if _, err := iss.Verify(tok); err == nil {
		t.Error("expected expired token to fail verification")
	}
}

func TestJWTIssuer_RejectsWrongSecret(t *testing.T) {
	iss1, _ := NewJWTIssuer("secret-one", time.Minute)
	iss2, _ := NewJWTIssuer("secret-two", time.Minute)

	tok, _ := iss1.Issue("user-123")
	if _, err := iss2.Verify(tok); err == nil {
		t.Error("expected token signed with a different secret to fail verification")
	}
}

func TestJWTIssuer_RejectsAlgNone(t *testing.T) {
	// Algorithm-confusion attack: a token claiming alg "none" must be
	// rejected outright, never accepted as if unsigned tokens were valid.
	iss, _ := NewJWTIssuer("test-secret", time.Minute)

	claims := accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "attacker"},
	}
	unsignedToken := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokStr, err := unsignedToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to construct test token: %v", err)
	}

	if _, err := iss.Verify(tokStr); err == nil {
		t.Error("expected alg:none token to be rejected, got nil error")
	}
}

func TestNewJWTIssuer_RejectsEmptySecret(t *testing.T) {
	if _, err := NewJWTIssuer("", time.Minute); err == nil {
		t.Error("expected error for empty secret, got nil")
	}
}

func TestNewJWTIssuer_RejectsInvalidTTL(t *testing.T) {
	if _, err := NewJWTIssuer("secret", 0); err == nil {
		t.Error("expected error for zero TTL, got nil")
	}
	if _, err := NewJWTIssuer("secret", -time.Minute); err == nil {
		t.Error("expected error for negative TTL, got nil")
	}
}
