package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidAccessToken = errors.New("token: access token invalid or expired")
)

// JWTIssuer mints and verifies the short-lived access tokens. claims is
// optional and nil unless the host configured a ClaimsProvider; a nil
// one means tokens carry exactly the registered claims below and nothing
// else, which is what every token looked like before the hook existed.
type JWTIssuer struct {
	secret []byte
	ttl    time.Duration
	claims ClaimsProvider
}

func NewJWTIssuer(secret string, ttl time.Duration) (*JWTIssuer, error) {
	return NewJWTIssuerWithClaims(secret, ttl, nil)
}

// NewJWTIssuerWithClaims is NewJWTIssuer plus a hook for the host's own
// claims. Separate constructor rather than a fourth parameter on the
// existing one, because NewJWTIssuer is public API in a released module
// and provider is the exception, not the norm — same reason
// security.NewRedisRateLimiterWithPrefix sits beside its plain form. A
// nil provider is accepted and is exactly equivalent to NewJWTIssuer.
func NewJWTIssuerWithClaims(secret string, ttl time.Duration, provider ClaimsProvider) (*JWTIssuer, error) {
	if secret == "" {
		return nil, ErrMissingJWTSecret
	}
	if ttl <= 0 {
		return nil, ErrInvalidTTL
	}
	return &JWTIssuer{secret: []byte(secret), ttl: ttl, claims: provider}, nil
}

// Issue mints an access token without a request context. Kept because it
// is public API and because a caller with nothing better to pass should
// not have to invent a context; every call site inside this module has a
// real one and uses IssueWithContext instead. With no ClaimsProvider
// configured the two are identical — the context is only ever handed
// onward to the provider, for cancellation and for whatever the host
// keeps in it.
func (j *JWTIssuer) Issue(userID string) (string, error) {
	return j.IssueWithContext(context.Background(), userID)
}

// IssueWithContext mints an access token for userID, consulting the
// configured ClaimsProvider if there is one.
//
// The provider cannot reach the registered claims: its whole return is
// checked against the reserved set before a single entry is merged, so a
// provider returning "sub" alongside ten legitimate claims produces
// ErrReservedClaim and no token, rather than a token whose subject is
// whatever it felt like. Same for a provider error — it fails the issue,
// and with it the login or refresh that asked for one. See
// ClaimsProvider's own doc comment for why that is deliberately stricter
// than the fail-open external checks elsewhere in the engine.
func (j *JWTIssuer) IssueWithContext(ctx context.Context, userID string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": userID,
		"iat": jwt.NewNumericDate(now),
		"exp": jwt.NewNumericDate(now.Add(j.ttl)),
	}

	if j.claims != nil {
		extra, err := j.claims.AccessTokenClaims(ctx, userID)
		if err != nil {
			// Both wrapped: ErrClaimsProvider so a caller can recognise the
			// class without knowing the host's own error types, and the
			// host's error so the one thing that can actually be fixed —
			// whatever its provider hit — survives the trip up through
			// Login's return.
			return "", fmt.Errorf("%w: %w", ErrClaimsProvider, err)
		}
		if err := checkExtraClaims(extra); err != nil {
			return "", err
		}
		for name, value := range extra {
			claims[name] = value
		}
	}

	// A claim value that will not marshal to JSON surfaces here, out of
	// SignedString, and takes the token with it — nothing is emitted
	// half-serialised.
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(j.secret)
}

// Verify returns the user ID a valid token was issued for, discarding any
// host claims. VerifyWithClaims is the same check and hands those back.
func (j *JWTIssuer) Verify(tokenStr string) (string, error) {
	subject, _, err := j.VerifyWithClaims(tokenStr)
	return subject, err
}

// VerifyWithClaims validates tokenStr and returns its subject together
// with whatever the host's ClaimsProvider put in it. The registered
// claims are stripped from the second return: they are the engine's
// bookkeeping, the subject is already the first return, and a host
// reading its own claims out of that map should not have to know which
// names to skip. Nil when there are none.
//
// Note that JSON numbers come back as float64, and that these claims
// were only ever as trustworthy as the provider that produced them —
// the signature proves this engine issued the token, not that the facts
// inside it are still true. A role revoked five minutes ago is still in
// a token minted ten minutes ago; that is the tradeoff every claim in a
// bearer token makes, and the reason for a short AccessTokenTTL.
func (j *JWTIssuer) VerifyWithClaims(tokenStr string) (string, map[string]any, error) {
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		// Reject any token not signed with the algorithm we issue —
		// prevents algorithm-confusion attacks (e.g. "alg: none").
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidAccessToken
		}
		return j.secret, nil
	},
		// Belt and braces over the keyfunc check above, both kept: the
		// keyfunc rejects a whole family (anything not HMAC), this pins the
		// one member of it we actually issue, and it is enforced by the
		// parser before the keyfunc is ever consulted.
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		// Every token this issuer mints sets exp. Requiring it refuses one
		// that does not — a token signed with this secret but no expiry
		// would otherwise verify forever.
		jwt.WithExpirationRequired(),
	)
	if err != nil || !parsed.Valid {
		return "", nil, ErrInvalidAccessToken
	}

	// MapClaims makes the subject a type assertion rather than a struct
	// field, so an absent or non-string "sub" has to be handled here. It
	// is an invalid token, not an empty user ID: returning "" with a nil
	// error would hand a caller an authenticated request belonging to
	// nobody.
	subject, ok := claims["sub"].(string)
	if !ok || subject == "" {
		return "", nil, ErrInvalidAccessToken
	}
	return subject, hostClaims(claims), nil
}

// hostClaims copies out everything that is not a registered claim,
// returning nil rather than an empty map when there is nothing.
func hostClaims(claims jwt.MapClaims) map[string]any {
	var out map[string]any
	for name, value := range claims {
		if IsReservedClaim(name) {
			continue
		}
		if out == nil {
			out = make(map[string]any, len(claims))
		}
		out[name] = value
	}
	return out
}
