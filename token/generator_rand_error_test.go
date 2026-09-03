package token

import (
	"errors"
	"testing"
)

// failingReader always errors — injected directly into a
// CryptoRandTokenGenerator instance (same package, unexported field)
// to deterministically exercise the New() error path. This never
// touches the real crypto/rand.Reader global — see randReader's doc
// comment in generator.go for why mutating that global directly isn't
// safe across platforms.
type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) {
	return 0, errors.New("simulated entropy source failure")
}

func TestCryptoRandTokenGenerator_New_PropagatesRandReadError(t *testing.T) {
	// Regression test: New() used to swallow a rand.Read failure and
	// return ("", nil) — an empty string treated as a valid token with
	// no error to catch it. It must now return the real error.
	g, err := NewCryptoRandTokenGenerator(32)
	if err != nil {
		t.Fatalf("unexpected error constructing generator: %v", err)
	}
	g.randReader = failingReader{}

	tok, err := g.New()
	if err == nil {
		t.Fatal("expected New() to return an error when the entropy source fails, got nil")
	}
	if tok != "" {
		t.Errorf("expected an empty token alongside the error, got %q", tok)
	}
}
