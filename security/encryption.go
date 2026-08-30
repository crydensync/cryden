package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

var (
	ErrMissingEncryptionKey = errors.New("security: encryption key is required")
	ErrCiphertextTooShort   = errors.New("security: ciphertext too short to contain a nonce")
)

// Encryptor defines reversible symmetric encryption of small secrets
// that must be recovered in plaintext later — unlike Hasher, which is
// deliberately one-way. A TOTP secret is the motivating case: the
// engine must decrypt it back to the raw value to validate a code
// against it, so hashing (as used for passwords/tokens) doesn't apply
// here. v2 ships one implementation: AESGCMEncryptor.
type Encryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// AESGCMEncryptor is the v2 Encryptor implementation.
type AESGCMEncryptor struct {
	key []byte // exactly 32 bytes, for AES-256
}

// NewAESGCMEncryptor derives a 32-byte AES-256 key from secret via
// SHA-256. Hashing here only normalizes an arbitrary-length input
// down to AES-256's required key size — it is not a KDF standing in
// for secret strength. secret should be configured with the same
// care as JWTSecret (long, random, out of source control), not a
// human-memorable passphrase.
func NewAESGCMEncryptor(secret string) (*AESGCMEncryptor, error) {
	if secret == "" {
		return nil, ErrMissingEncryptionKey
	}
	key := sha256.Sum256([]byte(secret))
	return &AESGCMEncryptor{key: key[:]}, nil
}

func (e *AESGCMEncryptor) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	// Nonce is prepended to the ciphertext — standard practice for
	// AES-GCM, since the nonce isn't secret, only single-use.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (e *AESGCMEncryptor) Decrypt(ciphertext string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", ErrCiphertextTooShort
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

var _ Encryptor = (*AESGCMEncryptor)(nil)
