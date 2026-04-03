package core

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "time"
)

// generateSecureID creates a unique ID with randomness to prevent collisions
func generateSecureID(prefix string) string {
    // 8 bytes of randomness (64 bits) + timestamp for uniqueness
    b := make([]byte, 8)
    if _, err := rand.Read(b); err != nil {
        // Fallback to timestamp only if rand fails
        return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
    }
    random := base64.RawURLEncoding.EncodeToString(b)
    return fmt.Sprintf("%s_%d_%s", prefix, time.Now().UnixNano(), random)
}

// generateID is kept for backward compatibility
func generateID() string {
    return generateSecureID("gen")
}
