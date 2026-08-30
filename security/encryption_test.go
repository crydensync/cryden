package security

import "testing"

func TestAESGCMEncryptor_EncryptDecryptRoundTrip(t *testing.T) {
	enc, err := NewAESGCMEncryptor("test-encryption-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plaintext := "JBSWY3DPEHPK3PXP" // example base32 TOTP secret
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if ciphertext == plaintext {
		t.Fatal("ciphertext must not equal the plaintext")
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestAESGCMEncryptor_DifferentNoncePerCall(t *testing.T) {
	// Two encryptions of the same plaintext must produce different
	// ciphertexts (random nonce per call) — an attacker comparing two
	// stored secrets should never be able to tell they're equal.
	enc, _ := NewAESGCMEncryptor("test-encryption-key")

	a, _ := enc.Encrypt("same-secret")
	b, _ := enc.Encrypt("same-secret")
	if a == b {
		t.Error("expected different ciphertexts for repeated encryption of the same plaintext")
	}
}

func TestAESGCMEncryptor_WrongKeyFailsToDecrypt(t *testing.T) {
	encA, _ := NewAESGCMEncryptor("key-a")
	encB, _ := NewAESGCMEncryptor("key-b")

	ciphertext, _ := encA.Encrypt("secret-value")
	if _, err := encB.Decrypt(ciphertext); err == nil {
		t.Error("expected decryption with the wrong key to fail")
	}
}

func TestNewAESGCMEncryptor_EmptyKeyRejected(t *testing.T) {
	if _, err := NewAESGCMEncryptor(""); err != ErrMissingEncryptionKey {
		t.Errorf("expected ErrMissingEncryptionKey, got %v", err)
	}
}
