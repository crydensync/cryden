package token

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const claimsTestSecret = "test-secret"

// staticClaims is the ordinary case: a provider that returns the same
// claims for anyone.
func staticClaims(claims map[string]any) ClaimsProvider {
	return ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
		return claims, nil
	})
}

func issuerWith(t *testing.T, provider ClaimsProvider) *JWTIssuer {
	t.Helper()
	iss, err := NewJWTIssuerWithClaims(claimsTestSecret, time.Minute, provider)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return iss
}

func TestIssueWithClaims_HostClaimsSurviveTheRoundTrip(t *testing.T) {
	iss := issuerWith(t, staticClaims(map[string]any{
		"role":   "admin",
		"tenant": "acme",
		"seats":  3,
	}))

	tok, err := iss.IssueWithContext(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	userID, claims, err := iss.VerifyWithClaims(tok)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if userID != "user-123" {
		t.Errorf("expected user-123, got %q", userID)
	}
	if claims["role"] != "admin" {
		t.Errorf("expected role admin, got %v", claims["role"])
	}
	if claims["tenant"] != "acme" {
		t.Errorf("expected tenant acme, got %v", claims["tenant"])
	}
	// Documented behaviour, not an accident: JSON has one number type and
	// the parser hands it back as float64.
	if seats, ok := claims["seats"].(float64); !ok || seats != 3 {
		t.Errorf("expected seats to come back as float64(3), got %T(%v)", claims["seats"], claims["seats"])
	}
}

func TestVerifyWithClaims_StripsRegisteredClaims(t *testing.T) {
	iss := issuerWith(t, staticClaims(map[string]any{"role": "admin"}))

	tok, err := iss.IssueWithContext(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}
	_, claims, err := iss.VerifyWithClaims(tok)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	if len(claims) != 1 {
		t.Fatalf("expected only the host's claim, got %v", claims)
	}
	for _, name := range ReservedClaimNames() {
		if _, present := claims[name]; present {
			t.Errorf("registered claim %q leaked into the host claims", name)
		}
	}
}

func TestVerifyWithClaims_NoProviderMeansNoClaims(t *testing.T) {
	iss, err := NewJWTIssuer(claimsTestSecret, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tok, err := iss.Issue("user-123")
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}
	userID, claims, err := iss.VerifyWithClaims(tok)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if userID != "user-123" {
		t.Errorf("expected user-123, got %q", userID)
	}
	if claims != nil {
		t.Errorf("expected nil claims without a provider, got %v", claims)
	}
}

func TestIssueWithClaims_EmptyAndNilMapsChangeNothing(t *testing.T) {
	for name, provider := range map[string]ClaimsProvider{
		"nil map":   staticClaims(nil),
		"empty map": staticClaims(map[string]any{}),
	} {
		t.Run(name, func(t *testing.T) {
			iss := issuerWith(t, provider)
			tok, err := iss.IssueWithContext(context.Background(), "user-123")
			if err != nil {
				t.Fatalf("issue failed: %v", err)
			}
			_, claims, err := iss.VerifyWithClaims(tok)
			if err != nil {
				t.Fatalf("verify failed: %v", err)
			}
			if claims != nil {
				t.Errorf("expected nil claims, got %v", claims)
			}
		})
	}
}

func TestIssueWithClaims_RefusesEveryReservedName(t *testing.T) {
	for _, name := range ReservedClaimNames() {
		t.Run(name, func(t *testing.T) {
			iss := issuerWith(t, staticClaims(map[string]any{name: "attacker"}))

			tok, err := iss.IssueWithContext(context.Background(), "user-123")
			if !errors.Is(err, ErrReservedClaim) {
				t.Fatalf("expected ErrReservedClaim for %q, got %v", name, err)
			}
			if tok != "" {
				t.Error("expected no token alongside the error")
			}
			// The message has to name the offender — a host debugging its own
			// provider gets no help from "a reserved claim" alone.
			if !strings.Contains(err.Error(), name) {
				t.Errorf("expected error to name the claim, got %q", err.Error())
			}
		})
	}
}

func TestIssueWithClaims_ReservedNameRejectsTheWholeSet(t *testing.T) {
	// All-or-nothing: the legitimate claims alongside "sub" do not make it
	// into a token either, because there is no token.
	iss := issuerWith(t, staticClaims(map[string]any{
		"role":   "admin",
		"tenant": "acme",
		"sub":    "attacker",
	}))

	if _, err := iss.IssueWithContext(context.Background(), "user-123"); !errors.Is(err, ErrReservedClaim) {
		t.Fatalf("expected ErrReservedClaim, got %v", err)
	}
}

func TestIssueWithClaims_ReservedMatchingIsCaseSensitive(t *testing.T) {
	// "SUB" is a different claim and an inert one — nothing reads it, so
	// nothing needs protecting from it.
	iss := issuerWith(t, staticClaims(map[string]any{"SUB": "shouting"}))

	tok, err := iss.IssueWithContext(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}
	userID, claims, err := iss.VerifyWithClaims(tok)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if userID != "user-123" {
		t.Errorf("expected the real subject, got %q", userID)
	}
	if claims["SUB"] != "shouting" {
		t.Errorf("expected SUB to pass through, got %v", claims["SUB"])
	}
}

func TestIssueWithClaims_RefusesEmptyClaimName(t *testing.T) {
	iss := issuerWith(t, staticClaims(map[string]any{"": "nameless"}))

	if _, err := iss.IssueWithContext(context.Background(), "user-123"); !errors.Is(err, ErrEmptyClaimName) {
		t.Fatalf("expected ErrEmptyClaimName, got %v", err)
	}
}

func TestIssueWithClaims_ProviderErrorFailsClosed(t *testing.T) {
	lookupFailed := errors.New("role lookup: connection refused")
	iss := issuerWith(t, ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
		return nil, lookupFailed
	}))

	tok, err := iss.IssueWithContext(context.Background(), "user-123")
	if tok != "" {
		t.Error("expected no token when the provider fails")
	}
	if !errors.Is(err, ErrClaimsProvider) {
		t.Errorf("expected ErrClaimsProvider, got %v", err)
	}
	// The host's own error has to survive too, or the only actionable half
	// of the failure is lost.
	if !errors.Is(err, lookupFailed) {
		t.Errorf("expected the provider's error to be wrapped, got %v", err)
	}
}

func TestIssueWithClaims_UnmarshalableValueFailsTheToken(t *testing.T) {
	iss := issuerWith(t, staticClaims(map[string]any{"pipe": make(chan int)}))

	tok, err := iss.IssueWithContext(context.Background(), "user-123")
	if err == nil {
		t.Fatal("expected a claim value that cannot be marshalled to fail the issue")
	}
	if tok != "" {
		t.Error("expected no token alongside the error")
	}
}

func TestClaimsFunc_ReceivesTheContextAndUserID(t *testing.T) {
	type key struct{}
	var gotUserID, gotTrace string

	iss := issuerWith(t, ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
		gotUserID = userID
		gotTrace, _ = ctx.Value(key{}).(string)
		return map[string]any{"role": "admin"}, nil
	}))

	ctx := context.WithValue(context.Background(), key{}, "trace-abc")
	if _, err := iss.IssueWithContext(ctx, "user-123"); err != nil {
		t.Fatalf("issue failed: %v", err)
	}
	if gotUserID != "user-123" {
		t.Errorf("expected the provider to be told which user, got %q", gotUserID)
	}
	if gotTrace != "trace-abc" {
		t.Errorf("expected the caller's context to reach the provider, got %q", gotTrace)
	}
}

func TestIssue_WithoutContextStillConsultsTheProvider(t *testing.T) {
	var called bool
	iss := issuerWith(t, ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
		called = true
		if ctx == nil {
			t.Error("expected a usable context, got nil")
		}
		return map[string]any{"role": "admin"}, nil
	}))

	tok, err := iss.Issue("user-123")
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}
	if !called {
		t.Error("expected the context-free Issue to consult the provider too")
	}
	if _, claims, err := iss.VerifyWithClaims(tok); err != nil || claims["role"] != "admin" {
		t.Errorf("expected the claim to be in the token, got %v (err %v)", claims, err)
	}
}

// signRaw mints a token this issuer would never produce, using the same
// secret — the shape an attacker has once a secret leaks, and the shape a
// second service sharing the secret might produce by accident.
func signRaw(t *testing.T, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(method, claims).SignedString([]byte(claimsTestSecret))
	if err != nil {
		t.Fatalf("failed to construct test token: %v", err)
	}
	return tok
}

func TestVerifyWithClaims_RequiresAnExpiry(t *testing.T) {
	iss := issuerWith(t, nil)
	tok := signRaw(t, jwt.SigningMethodHS256, jwt.MapClaims{"sub": "user-123"})

	if _, _, err := iss.VerifyWithClaims(tok); !errors.Is(err, ErrInvalidAccessToken) {
		t.Errorf("expected a token with no exp to be rejected, got %v", err)
	}
}

func TestVerifyWithClaims_RejectsADifferentHMACAlgorithm(t *testing.T) {
	// HS512 passes the keyfunc's "is it HMAC" check — it is. WithValidMethods
	// is what refuses it, which is why both are kept.
	iss := issuerWith(t, nil)
	tok := signRaw(t, jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": "user-123",
		"exp": jwt.NewNumericDate(time.Now().Add(time.Minute)),
	})

	if _, _, err := iss.VerifyWithClaims(tok); !errors.Is(err, ErrInvalidAccessToken) {
		t.Errorf("expected an HS512 token to be rejected, got %v", err)
	}
}

func TestVerifyWithClaims_RejectsAMissingOrNonStringSubject(t *testing.T) {
	iss := issuerWith(t, nil)
	exp := jwt.NewNumericDate(time.Now().Add(time.Minute))

	for name, claims := range map[string]jwt.MapClaims{
		"absent":     {"exp": exp},
		"empty":      {"sub": "", "exp": exp},
		"not-string": {"sub": 42, "exp": exp},
	} {
		t.Run(name, func(t *testing.T) {
			userID, _, err := iss.VerifyWithClaims(signRaw(t, jwt.SigningMethodHS256, claims))
			if !errors.Is(err, ErrInvalidAccessToken) {
				t.Errorf("expected rejection, got %v", err)
			}
			if userID != "" {
				t.Errorf("expected no user ID, got %q", userID)
			}
		})
	}
}

func TestVerifyWithClaims_RejectsAlgNoneCarryingHostClaims(t *testing.T) {
	// The alg:none case again, this time with claims attached: a forged
	// token must not get as far as having its claims read.
	iss := issuerWith(t, nil)
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub":  "attacker",
		"role": "admin",
		"exp":  jwt.NewNumericDate(time.Now().Add(time.Minute)),
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to construct test token: %v", err)
	}

	userID, claims, err := iss.VerifyWithClaims(unsigned)
	if !errors.Is(err, ErrInvalidAccessToken) {
		t.Errorf("expected alg:none to be rejected, got %v", err)
	}
	if userID != "" || claims != nil {
		t.Errorf("expected nothing back from a rejected token, got %q / %v", userID, claims)
	}
}

func TestReservedClaimNames_AreTheRegisteredSevenAndUneditable(t *testing.T) {
	names := ReservedClaimNames()
	want := []string{"aud", "exp", "iat", "iss", "jti", "nbf", "sub"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("expected %v, got %v", want, names)
	}

	names[0] = "not-a-claim"
	if !IsReservedClaim("aud") {
		t.Error("editing the returned slice changed what the check reads")
	}
	if IsReservedClaim("not-a-claim") {
		t.Error("editing the returned slice added a reserved name")
	}
}

func TestNewJWTIssuerWithClaims_ValidatesSecretAndTTL(t *testing.T) {
	provider := staticClaims(map[string]any{"role": "admin"})
	if _, err := NewJWTIssuerWithClaims("", time.Minute, provider); !errors.Is(err, ErrMissingJWTSecret) {
		t.Errorf("expected ErrMissingJWTSecret, got %v", err)
	}
	if _, err := NewJWTIssuerWithClaims("secret", 0, provider); !errors.Is(err, ErrInvalidTTL) {
		t.Errorf("expected ErrInvalidTTL, got %v", err)
	}
}
