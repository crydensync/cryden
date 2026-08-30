package token

import (
	"crypto/rand"
	"encoding/hex"
)

// TokenGenerator defines generation of opaque, cryptographically random
// refresh tokens. v2 ships one implementation: CryptoRandTokenGenerator.
// The raw token returned here is what's given to the caller — it is
// never persisted as-is; the engine hashes it (SHA-256) before storing
// in SessionStore. See token/refresh.go.
type TokenGenerator interface {
	New() (string, error)
}

// CryptoRandTokenGenerator is the v2 TokenGenerator implementation.
// Generates 32 raw random bytes (256 bits) via crypto/rand and
// hex-encodes them for safe storage/transport as a string.
type CryptoRandTokenGenerator struct {
	// ByteLength is the number of random bytes generated per token.
	// 32 bytes (256 bits) is the standard baseline for opaque tokens.
	ByteLength int
}

// NewCryptoRandTokenGenerator constructs a generator. byteLength must
// be set explicitly by the caller via Config; 32 is the recommended
// value if the caller has no specific reason to deviate.
func NewCryptoRandTokenGenerator(byteLength int) (*CryptoRandTokenGenerator, error) {
	if byteLength < 16 {
		// Reject anything below 128 bits — too weak for a session token.
		return nil, ErrTokenByteLengthTooShort
	}
	return &CryptoRandTokenGenerator{ByteLength: byteLength}, nil
}

func (g *CryptoRandTokenGenerator) New() (string, error) {
	buf := make([]byte, g.ByteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
