package token

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"

    "github.com/crydensync/cryden/internal/core"
)

// Service handles all token operations
type Service struct {
    hasher core.Hasher
}

// NewService creates a new token service
func NewService(hasher core.Hasher) *Service {
    return &Service{
        hasher: hasher,
    }
}

// RefreshTokenBundle contains all forms of a refresh token
type RefreshTokenBundle struct {
    PlainText   string // What client receives
    LookupHash  string // SHA256 for DB lookup (indexed)
    StorageHash string // bcrypt for DB storage (salted)
}

// GenerateRefreshToken creates a secure random token and its hashes
func (s *Service) GenerateRefreshToken() (*RefreshTokenBundle, error) {
    // 1. Generate cryptographically secure random token (32 bytes = 256 bits)
    token := make([]byte, 32)
    _, err := rand.Read(token)
    if err != nil {
        return nil, fmt.Errorf("failed to generate random token: %w", err)
    }
    
    // Encode as URL-safe base64 (no + or /, no padding)
    plainToken := base64.RawURLEncoding.EncodeToString(token)
    
    // 2. Generate SHA256 lookup hash (for fast DB indexing)
    sha := sha256.Sum256([]byte(plainToken))
    lookupHash := hex.EncodeToString(sha[:])
    
    // 3. Generate bcrypt storage hash (for secure verification)
    storageHash, err := s.hasher.Hash(plainToken)
    if err != nil {
        return nil, fmt.Errorf("failed to hash token: %w", err)
    }
    
    return &RefreshTokenBundle{
        PlainText:   plainToken,
        LookupHash:  lookupHash,
        StorageHash: storageHash,
    }, nil
}

// VerifyRefreshToken checks if a plain token matches a stored hash
func (s *Service) VerifyRefreshToken(plainToken, storageHash string) error {
    return s.hasher.Compare(plainToken, storageHash)
}
