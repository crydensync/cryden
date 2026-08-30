package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidPendingToken = errors.New("token: pending MFA token invalid or expired")

// mfaPendingTTL is fixed, not configurable via Config. A "password
// verified, awaiting second factor" window should always be short —
// TOTP codes themselves rotate every 30s — so making this a tuning
// knob would just invite a deployment to widen a narrow race into a
// standing credential.
const mfaPendingTTL = 5 * time.Minute

// MFAPendingIssuer issues and verifies short-lived, stateless tokens
// proving a caller already presented a correct password for the
// embedded userID and is now expected to complete login with a second
// factor. Never treat one of these as equivalent to a real access
// token — Verify checks a dedicated "typ" claim specifically to
// prevent that confusion, even though both token types are signed
// with the same secret.
type MFAPendingIssuer struct {
	secret []byte
}

// NewMFAPendingIssuer constructs an MFAPendingIssuer. secret must be
// non-empty — reuses Config.JWTSecret, same as JWTIssuer; there is no
// separate secret to configure for this token type.
func NewMFAPendingIssuer(secret string) (*MFAPendingIssuer, error) {
	if secret == "" {
		return nil, ErrMissingJWTSecret
	}
	return &MFAPendingIssuer{secret: []byte(secret)}, nil
}

type mfaPendingClaims struct {
	Typ string `json:"typ"`
	jwt.RegisteredClaims
}

// Issue creates a signed pending-login token for userID, expiring
// after mfaPendingTTL.
func (m *MFAPendingIssuer) Issue(userID string) (string, error) {
	now := time.Now()
	claims := mfaPendingClaims{
		Typ: "mfa_pending",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(mfaPendingTTL)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(m.secret)
}

// Verify checks the token's signature, expiry, and type claim,
// returning the embedded user ID if valid.
func (m *MFAPendingIssuer) Verify(tokenStr string) (string, error) {
	claims := &mfaPendingClaims{}
	parsed, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		// Reject any token not signed with the algorithm we issue —
		// prevents algorithm-confusion attacks (e.g. "alg: none").
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidPendingToken
		}
		return m.secret, nil
	})
	if err != nil || !parsed.Valid || claims.Typ != "mfa_pending" {
		return "", ErrInvalidPendingToken
	}
	return claims.Subject, nil
}
