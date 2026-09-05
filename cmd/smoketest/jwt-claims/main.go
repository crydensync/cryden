// Command jwt-claims is a standalone, no-database smoke test for
// extensible JWT claims: a host app attaching its own data — a role, a
// tenant — to every access token the engine issues, so a gateway holding
// a verified token can read it there instead of looking the user up
// again. What is under test is the whole round trip through the public
// facade (login, refresh, verify), the default that leaves tokens exactly
// as they were, and the four ways a provider is told no: a reserved claim
// name, an empty one, a value that will not serialise, and an error of its
// own. Plus the algorithm-confusion defences, which this item was
// required to strengthen and not weaken. Run with:
//
//	go run ./cmd/smoketest/jwt-claims
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/store/memory"
	"github.com/crydensync/cryden/v2/token"
	"github.com/golang-jwt/jwt/v5"
)

const (
	email    = "raymondproguy@dev.com"
	password = "Tr0ubl3-Fr33!2026"
	callerIP = "203.0.113.7"
	agent    = "smoketest-agent"
	// Known to this test on purpose: section 7 forges tokens with the
	// engine's own secret, which is the position an attacker is in after a
	// leak and the only position from which the signing-method checks are
	// the last line of defence.
	jwtSecret = "smoketest-jwt-secret"
)

var failures int

func main() {
	fmt.Println("cryden — extensible JWT claims smoke test")

	hostClaimsReachTheToken()
	theDefaultIsUnchanged()
	refreshReEvaluates()
	reservedNamesRefused()
	providerErrorsFailClosed()
	unusableClaimsRefused()
	forgedTokensStillRejected()
	whatEndsUpOnTheWire()

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
		return
	}
	fmt.Printf("%d CHECK(S) FAILED\n", failures)
	os.Exit(1)
}

// The point of the item: what the host put in comes back out, addressed
// to the right user, without the engine's own bookkeeping mixed in.
func hostClaimsReachTheToken() {
	section("Host claims survive the round trip")

	calls := 0
	engine, err := newEngine(token.ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
		calls++
		return map[string]any{"role": "admin", "tenant": "acme", "seats": 3}, nil
	}))
	check("engine wired with a ClaimsProvider", err)
	if err != nil {
		return
	}

	ctx := context.Background()
	user, err := cryden.SignUp(ctx, engine, email, password, callerIP)
	check("signed up", err)
	expectCount("signup asked the provider for nothing", calls, 0)

	tokens, err := cryden.Login(ctx, engine, email, password, callerIP, agent)
	check("logged in", err)
	expectCount("one login, one call to the provider", calls, 1)

	userID, claims, err := cryden.VerifyTokenWithClaims(engine, tokens.AccessToken)
	check("verified the access token", err)
	expectString("the token names the right user", userID, user.ID)
	expectString("role came back", str(claims["role"]), "admin")
	expectString("tenant came back", str(claims["tenant"]), "acme")

	// JSON has one number type; the parser hands integers back as float64.
	if seats, ok := claims["seats"].(float64); ok && seats == 3 {
		pass("a numeric claim came back as float64(3)")
	} else {
		fail(fmt.Sprintf("expected float64(3) for seats, got %T(%v)", claims["seats"], claims["seats"]))
	}

	expectCount("only the host's three claims are returned", len(claims), 3)
	for _, name := range token.ReservedClaimNames() {
		if _, present := claims[name]; present {
			fail(fmt.Sprintf("registered claim %q leaked into the host's claims", name))
			return
		}
	}
	pass("no registered claim leaked into them")

	plain, err := cryden.VerifyToken(engine, tokens.AccessToken)
	check("VerifyToken still works on the same token", err)
	expectString("and agrees about the user", plain, user.ID)
}

// Nothing changes for a host that never sets AccessTokenClaims — the
// whole feature has to be invisible until asked for.
func theDefaultIsUnchanged() {
	section("No provider configured")

	engine, err := newEngine(nil)
	check("engine wired without a ClaimsProvider", err)
	if err != nil {
		return
	}

	ctx := context.Background()
	user, err := cryden.SignUp(ctx, engine, email, password, callerIP)
	check("signed up", err)

	tokens, err := cryden.Login(ctx, engine, email, password, callerIP, agent)
	check("logged in", err)

	userID, claims, err := cryden.VerifyTokenWithClaims(engine, tokens.AccessToken)
	check("verified the access token", err)
	expectString("the user ID is there as always", userID, user.ID)
	if claims != nil {
		fail(fmt.Sprintf("expected no claims at all, got %v", claims))
		return
	}
	pass("no host claims, and nil rather than an empty map")

	names := claimNames(tokens.AccessToken)
	expectString("the token carries exactly sub, iat and exp", strings.Join(names, ","), "exp,iat,sub")
}

// Claims are re-read on every access token, not copied forward from the
// previous one — which is what makes a role change visible without
// forcing the user to log in again, and also what puts the provider on
// the refresh path every ~15 minutes per active session.
func refreshReEvaluates() {
	section("Refresh re-evaluates the claims")

	calls := 0
	engine, err := newEngine(token.ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
		calls++
		if calls == 1 {
			return map[string]any{"role": "member"}, nil
		}
		return map[string]any{"role": "admin"}, nil
	}))
	check("engine wired", err)
	if err != nil {
		return
	}

	ctx := context.Background()
	if _, err := cryden.SignUp(ctx, engine, email, password, callerIP); err != nil {
		fail(fmt.Sprintf("signup failed: %v", err))
		return
	}
	first, err := cryden.Login(ctx, engine, email, password, callerIP, agent)
	check("logged in", err)

	_, claims, err := cryden.VerifyTokenWithClaims(engine, first.AccessToken)
	check("verified the first token", err)
	expectString("it says member", str(claims["role"]), "member")

	// The promotion happens out here, in the host's own data — the engine
	// is never told about it and does not need to be.
	second, err := cryden.RefreshToken(ctx, engine, first.RefreshToken)
	check("refreshed", err)

	_, claims, err = cryden.VerifyTokenWithClaims(engine, second.AccessToken)
	check("verified the refreshed token", err)
	expectString("the new token says admin", str(claims["role"]), "admin")
	expectCount("one call per access token, no more", calls, 2)

	// The old access token is still valid until it expires, carrying the
	// old role. Not a bug to fix here — it is what a bearer token is — but
	// it is the reason AccessTokenTTL defaults to fifteen minutes.
	_, stale, err := cryden.VerifyTokenWithClaims(engine, first.AccessToken)
	check("the old token still verifies until it expires", err)
	expectString("and still carries the old role", str(stale["role"]), "member")
}

// The security core of the item. A provider able to set "sub" is a
// provider able to mint a token for another user, since that is where
// Verify reads the user ID from; the whole registered set is refused so
// the rule does not need revisiting when the engine starts setting one of
// the others.
func reservedNamesRefused() {
	section("Reserved claim names are refused")

	for _, name := range token.ReservedClaimNames() {
		reserved := name
		engine, err := newEngine(token.ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
			// A real claim alongside the forbidden one: all-or-nothing means
			// this legitimate claim does not get through either.
			return map[string]any{"role": "admin", reserved: "attacker"}, nil
		}))
		if err != nil {
			fail(fmt.Sprintf("engine wiring failed: %v", err))
			return
		}

		ctx := context.Background()
		user, err := cryden.SignUp(ctx, engine, email, password, callerIP)
		if err != nil {
			fail(fmt.Sprintf("signup failed: %v", err))
			return
		}

		tokens, err := cryden.Login(ctx, engine, email, password, callerIP, agent)
		switch {
		case !errors.Is(err, token.ErrReservedClaim):
			fail(fmt.Sprintf("%q: expected ErrReservedClaim, got %v", reserved, err))
		case !strings.Contains(err.Error(), reserved):
			fail(fmt.Sprintf("%q: the error does not name the offending claim: %v", reserved, err))
		case tokens.AccessToken != "" || tokens.RefreshToken != "":
			fail(fmt.Sprintf("%q: tokens handed out despite the error", reserved))
		default:
			pass(fmt.Sprintf("%q refused, by name, with no token issued", reserved))
		}

		sessions, err := cryden.ListSessions(ctx, engine, user.ID)
		if err != nil || len(sessions) != 0 {
			fail(fmt.Sprintf("%q: expected no session left behind, got %d (err %v)", reserved, len(sessions), err))
			continue
		}
		pass(fmt.Sprintf("%q left no session behind either", reserved))
	}

	// Case-sensitive, because JSON keys are — and "SUB" is a claim nothing
	// reads, so there is nothing to protect it from.
	engine, err := newEngine(token.ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
		return map[string]any{"SUB": "shouting"}, nil
	}))
	check("engine wired for the case-sensitivity check", err)
	if err != nil {
		return
	}
	ctx := context.Background()
	user, _ := cryden.SignUp(ctx, engine, email, password, callerIP)
	tokens, err := cryden.Login(ctx, engine, email, password, callerIP, agent)
	check("a differently-cased \"SUB\" is allowed through", err)
	userID, claims, err := cryden.VerifyTokenWithClaims(engine, tokens.AccessToken)
	check("the token verifies", err)
	expectString("the real subject is untouched", userID, user.ID)
	expectString("and SUB is just another host claim", str(claims["SUB"]), "shouting")
}

// Deliberately the opposite of the breached-password check two packages
// over, which lets a signup through when it cannot reach its service.
// Claims are authorization data: a token missing one may be read as
// permission rather than denial, so the engine declines to issue it.
func providerErrorsFailClosed() {
	section("A provider error fails the token, not just the claim")

	lookupFailed := errors.New("role lookup: connection refused")
	calls := 0
	engine, err := newEngine(token.ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
		calls++
		if calls == 1 {
			return map[string]any{"role": "member"}, nil
		}
		return nil, lookupFailed
	}))
	check("engine wired", err)
	if err != nil {
		return
	}

	ctx := context.Background()
	user, err := cryden.SignUp(ctx, engine, email, password, callerIP)
	check("signed up", err)

	// First login succeeds — the provider is only broken from its second
	// call, so this proves the failures below are the provider's and not
	// the engine's.
	first, err := cryden.Login(ctx, engine, email, password, callerIP, agent)
	check("first login worked", err)

	// Refresh: the rotation has already happened by the time the claims
	// lookup runs, so this costs the session, not just the request.
	if _, err := cryden.RefreshToken(ctx, engine, first.RefreshToken); errors.Is(err, token.ErrClaimsProvider) {
		pass("refresh failed with ErrClaimsProvider")
	} else {
		fail(fmt.Sprintf("expected ErrClaimsProvider from refresh, got %v", err))
	}
	if _, err := cryden.RefreshToken(ctx, engine, first.RefreshToken); err != nil {
		pass("and the refresh token is spent — the session is gone, log in again")
	} else {
		fail("expected the rotated refresh token to be unusable")
	}

	tokens, err := cryden.Login(ctx, engine, email, password, callerIP, agent)
	switch {
	case !errors.Is(err, token.ErrClaimsProvider):
		fail(fmt.Sprintf("expected ErrClaimsProvider from login, got %v", err))
	case !errors.Is(err, lookupFailed):
		fail(fmt.Sprintf("the provider's own error did not survive: %v", err))
	case tokens.AccessToken != "":
		fail("an access token was issued despite the provider failing")
	default:
		pass("login failed closed, wrapping both the sentinel and the cause")
	}

	// The reason finishLogin issues the token before storing the session:
	// a session written for a login that then failed would sit there until
	// it expired, with no refresh token anywhere able to use it.
	sessions, err := cryden.ListSessions(ctx, engine, user.ID)
	check("listed the user's sessions", err)
	expectCount("the failed login left no session behind", len(sessions), 0)
}

// Two more ways a provider can be wrong, both caught before a token
// exists rather than producing a token that is quietly not what the host
// thinks it is.
func unusableClaimsRefused() {
	section("Unusable claims are refused")

	cases := []struct {
		step   string
		claims map[string]any
		want   error
	}{
		{"a claim with an empty name", map[string]any{"": "nameless"}, token.ErrEmptyClaimName},
		// No sentinel for this one: the JSON error out of the signer names
		// the type, which is more useful than anything this package could
		// say about it.
		{"a value that will not marshal to JSON", map[string]any{"pipe": make(chan int)}, nil},
	}

	for _, tc := range cases {
		claims := tc.claims
		engine, err := newEngine(token.ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
			return claims, nil
		}))
		if err != nil {
			fail(fmt.Sprintf("engine wiring failed: %v", err))
			return
		}

		ctx := context.Background()
		if _, err := cryden.SignUp(ctx, engine, email, password, callerIP); err != nil {
			fail(fmt.Sprintf("signup failed: %v", err))
			return
		}
		tokens, err := cryden.Login(ctx, engine, email, password, callerIP, agent)
		switch {
		case err == nil:
			fail(fmt.Sprintf("%s: expected the login to fail", tc.step))
		case tc.want != nil && !errors.Is(err, tc.want):
			fail(fmt.Sprintf("%s: expected %v, got %v", tc.step, tc.want, err))
		case tokens.AccessToken != "":
			fail(fmt.Sprintf("%s: a token was issued anyway", tc.step))
		default:
			pass(fmt.Sprintf("%s is refused", tc.step))
		}
	}
}

// The constraint the item was handed: none of the above may weaken the
// algorithm-confusion protection. These tokens are all forged with the
// engine's real secret, so the signature check cannot help — only the
// signing-method and expiry rules can.
func forgedTokensStillRejected() {
	section("Forged and malformed tokens are still rejected")

	engine, err := newEngine(token.ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
		return map[string]any{"role": "member"}, nil
	}))
	check("engine wired", err)
	if err != nil {
		return
	}
	ctx := context.Background()
	if _, err := cryden.SignUp(ctx, engine, email, password, callerIP); err != nil {
		fail(fmt.Sprintf("signup failed: %v", err))
		return
	}
	honest, err := cryden.Login(ctx, engine, email, password, callerIP, agent)
	check("got one honest token to compare against", err)

	exp := jwt.NewNumericDate(time.Now().Add(time.Minute))
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "attacker", "role": "admin", "exp": exp,
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		fail(fmt.Sprintf("could not build the alg:none token: %v", err))
		return
	}

	forged := []struct {
		step  string
		token string
	}{
		{"alg:none, self-promoted to admin", unsigned},
		// HS512 is HMAC, so the keyfunc's family check passes it; the
		// explicit HS256 pin is what refuses it.
		{"HS512 signed with the real secret", sign(jwt.SigningMethodHS512, jwt.MapClaims{"sub": "attacker", "exp": exp})},
		{"HS256 with no expiry — otherwise valid forever", sign(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "attacker"})},
		{"HS256 with no subject", sign(jwt.SigningMethodHS256, jwt.MapClaims{"role": "admin", "exp": exp})},
		{"HS256 with a numeric subject", sign(jwt.SigningMethodHS256, jwt.MapClaims{"sub": 42, "exp": exp})},
		{"already expired", sign(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "attacker", "exp": jwt.NewNumericDate(time.Now().Add(-time.Hour))})},
		{"an honest token with one byte of its payload changed", tamper(honest.AccessToken)},
		{"empty string", ""},
	}

	for _, f := range forged {
		userID, claims, err := cryden.VerifyTokenWithClaims(engine, f.token)
		switch {
		case !errors.Is(err, token.ErrInvalidAccessToken):
			fail(fmt.Sprintf("%s: expected ErrInvalidAccessToken, got %v", f.step, err))
		case userID != "" || claims != nil:
			fail(fmt.Sprintf("%s: rejected but still returned %q / %v", f.step, userID, claims))
		default:
			pass(fmt.Sprintf("%s: rejected, nothing returned", f.step))
		}
	}

	// And the honest one still passes, so the above is not just "everything
	// fails."
	if _, claims, err := cryden.VerifyTokenWithClaims(engine, honest.AccessToken); err != nil || str(claims["role"]) != "member" {
		fail(fmt.Sprintf("the honest token stopped working: %v / %v", claims, err))
		return
	}
	pass("the honest token still verifies and still carries its claim")
}

// What a host actually has to reason about: the claims are in the payload
// in the clear, base64 and not encryption, and they travel in every
// Authorization header the client sends.
func whatEndsUpOnTheWire() {
	section("What the token actually contains")

	engine, err := newEngine(token.ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
		return map[string]any{"role": "admin", "tenant": "acme"}, nil
	}))
	check("engine wired", err)
	if err != nil {
		return
	}
	ctx := context.Background()
	if _, err := cryden.SignUp(ctx, engine, email, password, callerIP); err != nil {
		fail(fmt.Sprintf("signup failed: %v", err))
		return
	}
	tokens, err := cryden.Login(ctx, engine, email, password, callerIP, agent)
	check("logged in", err)

	names := claimNames(tokens.AccessToken)
	expectString("the payload holds exactly the engine's three plus the host's two",
		strings.Join(names, ","), "exp,iat,role,sub,tenant")

	payload := decodePayload(tokens.AccessToken)
	if strings.Contains(payload, "\"role\":\"admin\"") {
		pass("readable by anyone holding the token — base64, not encryption")
	} else {
		fail("could not find the claim in the decoded payload: " + payload)
	}
	fmt.Println("  payload:", payload)
	fmt.Printf("  token length: %d bytes, all of it sent in every Authorization header\n", len(tokens.AccessToken))
}

func newEngine(provider token.ClaimsProvider) (*cryden.Engine, error) {
	return cryden.New(cryden.Config{
		JWTSecret: jwtSecret,
		Users:     memory.NewUserStore(),
		Sessions:  memory.NewSessionStore(),
		Audit:     memory.NewAuditStore(),
		// Repeated logins from one address are this test's normal shape,
		// not an attack on it.
		RateLimitAttempts: 1000,
		AccessTokenClaims: provider,
		// The engine logs a dozen lines per login; this test is about the
		// ✓/✗ lines, so those go nowhere.
		Logger: logger.NewNopLogger(),
	})
}

// sign mints a token with the engine's own secret — the point being that
// the signature will check out and something else has to refuse it.
func sign(method jwt.SigningMethod, claims jwt.MapClaims) string {
	signed, err := jwt.NewWithClaims(method, claims).SignedString([]byte(jwtSecret))
	if err != nil {
		fail(fmt.Sprintf("could not build a test token: %v", err))
		return ""
	}
	return signed
}

// tamper flips a character in the payload, leaving the signature behind.
func tamper(tokenStr string) string {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 || len(parts[1]) == 0 {
		return tokenStr
	}
	swap := byte('A')
	if parts[1][0] == 'A' {
		swap = 'B'
	}
	parts[1] = string(swap) + parts[1][1:]
	return strings.Join(parts, ".")
}

func decodePayload(tokenStr string) string {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	return string(raw)
}

// claimNames lists what is in the payload, sorted, without verifying —
// this is the view an attacker or a curious client has.
func claimNames(tokenStr string) []string {
	var claims map[string]any
	if err := json.Unmarshal([]byte(decodePayload(tokenStr)), &claims); err != nil {
		return nil
	}
	names := make([]string, 0, len(claims))
	for name := range claims {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func str(value any) string {
	s, _ := value.(string)
	return s
}

func section(name string) {
	fmt.Printf("\n— %s\n", name)
}

func check(step string, err error) {
	if err != nil {
		fail(fmt.Sprintf("%s: unexpected error: %v", step, err))
		return
	}
	pass(step)
}

func expectString(step, got, want string) {
	if got != want {
		fail(fmt.Sprintf("%s: got %q, want %q", step, got, want))
		return
	}
	pass(step)
}

func expectCount(step string, got, want int) {
	if got != want {
		fail(fmt.Sprintf("%s: got %d, want %d", step, got, want))
		return
	}
	pass(step)
}

func pass(step string) {
	fmt.Println("✓", step)
}

func fail(msg string) {
	failures++
	fmt.Println("✗", msg)
}
