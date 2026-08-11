package security

import "testing"

func TestBcryptHasher_HashAndCompare(t *testing.T) {
	h, err := NewBcryptHasher(4) // low cost for fast tests
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hash, err := h.Hash("correct-password")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}
	if hash == "correct-password" {
		t.Fatal("hash must not equal the raw password")
	}

	if err := h.Compare(hash, "correct-password"); err != nil {
		t.Errorf("expected correct password to compare successfully, got: %v", err)
	}

	if err := h.Compare(hash, "wrong-password"); err == nil {
		t.Error("expected wrong password to fail comparison, got nil error")
	}
}

func TestNewBcryptHasher_RejectsInvalidCost(t *testing.T) {
	if _, err := NewBcryptHasher(1); err == nil {
		t.Error("expected error for cost below bcrypt.MinCost, got nil")
	}
	if _, err := NewBcryptHasher(100); err == nil {
		t.Error("expected error for cost above bcrypt.MaxCost, got nil")
	}
}

func TestBcryptHasher_SameInputDifferentHashes(t *testing.T) {
	// bcrypt salts automatically — hashing the same password twice
	// must never produce the same hash.
	h, _ := NewBcryptHasher(4)
	h1, _ := h.Hash("same-password")
	h2, _ := h.Hash("same-password")
	if h1 == h2 {
		t.Error("expected different hashes for the same password due to salting")
	}
}
