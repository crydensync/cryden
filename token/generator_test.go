package token

import "testing"

func TestCryptoRandTokenGenerator_ProducesUniqueTokens(t *testing.T) {
	g, err := NewCryptoRandTokenGenerator(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		tok, err := g.New()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if seen[tok] {
			t.Fatalf("duplicate token generated: %s", tok)
		}
		seen[tok] = true
	}
}

func TestNewCryptoRandTokenGenerator_RejectsTooShort(t *testing.T) {
	if _, err := NewCryptoRandTokenGenerator(8); err == nil {
		t.Error("expected error for byte length below 16, got nil")
	}
}

func TestHashToken_Deterministic(t *testing.T) {
	if HashToken("same-input") != HashToken("same-input") {
		t.Error("expected HashToken to be deterministic for the same input")
	}
	if HashToken("input-a") == HashToken("input-b") {
		t.Error("expected different inputs to produce different hashes")
	}
}
