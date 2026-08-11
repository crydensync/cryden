package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidAccessToken = errors.New("token: access token invalid or expired")
)

// JWTIssuer issues and verifies short-lived, stateless access tokens.
// Unlike refresh tokens, access tokens are never persisted or looked
// up in the DB — validity is proven entirely by signature + expiry.
//
// Secret and TTL must be set explicitly at construction — no default
// secret exists anywhere in this package (see NewJWTIssuer).
type JWTIssuer struct {
	secret []byte
	ttl    time.Duration
}

// NewJWTIssuer constructs a JWTIssuer. secret must be non-empty — the
// engine fails construction entirely if no secret is configured
// (see cryden.New / Config validation), so an empty secret reaching
// here would already be a bug upstream, not something to default past.
func NewJWTIssuer(secret string, ttl time.Duration) (*JWTIssuer, error) {
	if secret == "" {
		return nil, ErrMissingJWTSecret
	}
	if ttl <= 0 {
		return nil, ErrInvalidTTL
	}
	return &JWTIssuer{secret: []byte(secret), ttl: ttl}, nil
}

type accessClaims struct {
	jwt.RegisteredClaims
}

// Issue creates a signed access token for userID, expiring after the
// issuer's configured TTL.
func (j *JWTIssuer) Issue(userID string) (string, error) {
	now := time.Now()
	cliams := accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.ttl)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, cliams)
	return t.SignedString(j.secret)
}

// Verify checks the token's signature and expiry, returning the
// embedded user ID if valid.
func (j *JWTIssuer) Verify(tokenStr string) (string, error) {
	claims := &accessClaims{}
	parsed, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		// Reject any token not signed with the algorithm we issue —
		// prevents algorithm-confusion attacks (e.g. "alg: none").
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidAccessToken
		}
		return j.secret, nil
	})
	if err != nil || !parsed.Valid {
		return "", ErrInvalidAccessToken
	}
	return claims.Subject, nil
}
