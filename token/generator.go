package token

import (
	"crypto/rand"
	"encoding/hex"
	"io"
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
	// randReader defaults to crypto/rand.Reader (set by
	// NewCryptoRandTokenGenerator) and is never exposed publicly.
	// Deliberately injectable rather than calling crypto/rand.Read
	// directly, so a failure path can be tested by swapping this
	// field on a same-package instance — mutating the real global
	// crypto/rand.Reader instead (the previous approach) is not
	// portable: on at least one real platform, a failed read through
	// the actual global triggers the Go runtime's own unrecoverable
	// fatal-error path instead of returning a normal error, crashing
	// the whole test binary rather than failing one test.
	randReader io.Reader
}

// NewCryptoRandTokenGenerator constructs a generator. byteLength must
// be set explicitly by the caller via Config; 32 is the recommended
// value if the caller has no specific reason to deviate.
func NewCryptoRandTokenGenerator(byteLength int) (*CryptoRandTokenGenerator, error) {
	if byteLength < 16 {
		// Reject anything below 128 bits — too weak for a session token.
		return nil, ErrTokenByteLengthTooShort
	}
	return &CryptoRandTokenGenerator{ByteLength: byteLength, randReader: rand.Reader}, nil
}

func (g *CryptoRandTokenGenerator) New() (string, error) {
	buf := make([]byte, g.ByteLength)
	if _, err := io.ReadFull(g.randReader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
