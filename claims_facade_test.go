package cryden

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/crydensync/cryden/v2/token"
)

const (
	claimsEmail    = "raymondproguy@dev.com"
	claimsPassword = "Tr0ubl3-Fr33!2026"
)

// countingProvider records what the engine asked it for, so a test can
// assert not just the claim in the token but which user it was asked
// about and how many times.
type countingProvider struct {
	calls    atomic.Int64
	lastUser atomic.Value
	claims   func(n int64) (map[string]any, error)
}

func (p *countingProvider) AccessTokenClaims(ctx context.Context, userID string) (map[string]any, error) {
	n := p.calls.Add(1)
	p.lastUser.Store(userID)
	return p.claims(n)
}

func engineWithClaims(t *testing.T, provider token.ClaimsProvider) *Engine {
	t.Helper()
	cfg := validConfig()
	cfg.AccessTokenClaims = provider
	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return engine
}

func TestLogin_AttachesHostClaimsToTheAccessToken(t *testing.T) {
	provider := &countingProvider{claims: func(int64) (map[string]any, error) {
		return map[string]any{"role": "admin", "tenant": "acme"}, nil
	}}
	engine := engineWithClaims(t, provider)
	ctx := context.Background()

	user, err := SignUp(ctx, engine, claimsEmail, claimsPassword, "1.2.3.4")
	if err != nil {
		t.Fatalf("signup failed: %v", err)
	}
	// SignUp issues no access token, so nothing has asked the provider yet.
	if got := provider.calls.Load(); got != 0 {
		t.Errorf("expected the provider untouched by signup, called %d times", got)
	}

	tokens, err := Login(ctx, engine, claimsEmail, claimsPassword, "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	userID, claims, err := VerifyTokenWithClaims(engine, tokens.AccessToken)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if userID != user.ID {
		t.Errorf("expected %s, got %s", user.ID, userID)
	}
	if claims["role"] != "admin" || claims["tenant"] != "acme" {
		t.Errorf("expected the host's claims in the token, got %v", claims)
	}
	if got := provider.lastUser.Load(); got != user.ID {
		t.Errorf("expected the provider to be told %s, got %v", user.ID, got)
	}
	// VerifyToken is the same check without the claims, and still works.
	if plain, err := VerifyToken(engine, tokens.AccessToken); err != nil || plain != user.ID {
		t.Errorf("expected VerifyToken to agree, got %q (err %v)", plain, err)
	}
}

func TestRefreshToken_ReEvaluatesHostClaims(t *testing.T) {
	// A promotion between the login and the refresh: the point of
	// re-evaluating rather than copying the previous token's claims forward
	// is that the new access token reflects it.
	provider := &countingProvider{claims: func(n int64) (map[string]any, error) {
		if n == 1 {
			return map[string]any{"role": "member"}, nil
		}
		return map[string]any{"role": "admin"}, nil
	}}
	engine := engineWithClaims(t, provider)
	ctx := context.Background()

	SignUp(ctx, engine, claimsEmail, claimsPassword, "1.2.3.4")
	first, err := Login(ctx, engine, claimsEmail, claimsPassword, "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if _, claims, _ := VerifyTokenWithClaims(engine, first.AccessToken); claims["role"] != "member" {
		t.Fatalf("expected role member on the first token, got %v", claims)
	}

	second, err := RefreshToken(ctx, engine, first.RefreshToken)
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	_, claims, err := VerifyTokenWithClaims(engine, second.AccessToken)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if claims["role"] != "admin" {
		t.Errorf("expected the refreshed token to carry role admin, got %v", claims)
	}
	if got := provider.calls.Load(); got != 2 {
		t.Errorf("expected one call per access token, got %d", got)
	}
}

func TestVerifyTokenWithClaims_NilWithoutAProvider(t *testing.T) {
	engine, err := New(validConfig())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	ctx := context.Background()

	SignUp(ctx, engine, claimsEmail, claimsPassword, "1.2.3.4")
	tokens, err := Login(ctx, engine, claimsEmail, claimsPassword, "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	userID, claims, err := VerifyTokenWithClaims(engine, tokens.AccessToken)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if userID == "" {
		t.Error("expected a user ID")
	}
	if claims != nil {
		t.Errorf("expected nil claims with no provider configured, got %v", claims)
	}
}

func TestLogin_ProviderErrorFailsTheLoginAndLeavesNoSession(t *testing.T) {
	lookupFailed := errors.New("role lookup: connection refused")
	provider := &countingProvider{claims: func(int64) (map[string]any, error) {
		return nil, lookupFailed
	}}
	engine := engineWithClaims(t, provider)
	ctx := context.Background()

	user, err := SignUp(ctx, engine, claimsEmail, claimsPassword, "1.2.3.4")
	if err != nil {
		t.Fatalf("signup failed: %v", err)
	}

	tokens, err := Login(ctx, engine, claimsEmail, claimsPassword, "1.2.3.4", "test-agent")
	if !errors.Is(err, token.ErrClaimsProvider) {
		t.Fatalf("expected the login to fail closed with ErrClaimsProvider, got %v", err)
	}
	if !errors.Is(err, lookupFailed) {
		t.Errorf("expected the provider's own error to survive, got %v", err)
	}
	if tokens.AccessToken != "" || tokens.RefreshToken != "" {
		t.Error("expected no tokens from a failed login")
	}

	// The reason finishLogin issues before storing: a session created for a
	// login that then failed would sit in the store until it expired, with
	// no refresh token in anyone's hands able to use it.
	sessions, err := ListSessions(ctx, engine, user.ID)
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("expected no session left behind, got %d", len(sessions))
	}
}

func TestLogin_ReservedClaimFailsTheLogin(t *testing.T) {
	// The attack this closes: a provider (or a bug in one) setting "sub"
	// would otherwise mint a token authenticating as somebody else.
	provider := &countingProvider{claims: func(int64) (map[string]any, error) {
		return map[string]any{"sub": "somebody-else", "role": "admin"}, nil
	}}
	engine := engineWithClaims(t, provider)
	ctx := context.Background()

	user, _ := SignUp(ctx, engine, claimsEmail, claimsPassword, "1.2.3.4")
	if _, err := Login(ctx, engine, claimsEmail, claimsPassword, "1.2.3.4", "test-agent"); !errors.Is(err, token.ErrReservedClaim) {
		t.Fatalf("expected ErrReservedClaim, got %v", err)
	}

	sessions, _ := ListSessions(ctx, engine, user.ID)
	if len(sessions) != 0 {
		t.Errorf("expected no session left behind, got %d", len(sessions))
	}
}

func TestRefreshToken_ProviderErrorCostsTheSession(t *testing.T) {
	// Pinning the consequence rather than endorsing it: the rotation has
	// already happened when the claims lookup fails, so the refresh token
	// the caller is holding is spent and the session is gone. Failing
	// closed is still the right call — an access token missing its claims
	// is one a gateway may read permissively — but a host wiring a flaky
	// provider should know this is the cost.
	provider := &countingProvider{claims: func(n int64) (map[string]any, error) {
		if n == 1 {
			return map[string]any{"role": "member"}, nil
		}
		return nil, errors.New("role lookup: connection refused")
	}}
	engine := engineWithClaims(t, provider)
	ctx := context.Background()

	SignUp(ctx, engine, claimsEmail, claimsPassword, "1.2.3.4")
	first, err := Login(ctx, engine, claimsEmail, claimsPassword, "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if _, err := RefreshToken(ctx, engine, first.RefreshToken); !errors.Is(err, token.ErrClaimsProvider) {
		t.Fatalf("expected ErrClaimsProvider, got %v", err)
	}
	if _, err := RefreshToken(ctx, engine, first.RefreshToken); err == nil {
		t.Error("expected the spent refresh token to be unusable afterwards")
	}
}
