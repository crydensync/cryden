package token

import (
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

// failingReader always errors — swapped in for crypto/rand.Reader to
// deterministically exercise the rand.Read failure path, which never
// fails in practice under normal conditions.
type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) {
	return 0, errors.New("simulated entropy source failure")
}

func TestCryptoRandTokenGenerator_New_PropagatesRandReadError(t *testing.T) {
	// Regression test: New() used to swallow a rand.Read failure and
	// return ("", nil) — an empty string treated as a valid token
	// with no error to catch it. It must now return the real error.
	original := rand.Reader
	rand.Reader = failingReader{}
	defer func() { rand.Reader = original }()

	g, err := NewCryptoRandTokenGenerator(32)
	if err != nil {
		t.Fatalf("unexpected error constructing generator: %v", err)
	}

	tok, err := g.New()
	if err == nil {
		t.Fatal("expected New() to return an error when rand.Read fails, got nil")
	}
	if tok != "" {
		t.Errorf("expected an empty token alongside the error, got %q", tok)
	}
}

var _ io.Reader = failingReader{}
