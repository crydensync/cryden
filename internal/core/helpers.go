package core

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "time"
)

// getClientIP returns client IP from context or default
// In production, users will set this via middleware
// For now, this works for all tests and examples
func getClientIP(ctx context.Context) string {
    // Try to get from context (if set by middleware)
    if ip := ctx.Value("client_ip"); ip != nil {
        if ipStr, ok := ip.(string); ok && ipStr != "" {
            return ipStr
        }
    }
    
    // Default for testing/development
    return "127.0.0.1"
}

// generateSecureID creates a unique ID with randomness
func generateSecureID(prefix string) string {
    b := make([]byte, 8)
    if _, err := rand.Read(b); err != nil {
        // Fallback if rand fails (very rare)
        return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
    }
    random := base64.RawURLEncoding.EncodeToString(b)
    return fmt.Sprintf("%s_%d_%s", prefix, time.Now().UnixNano(), random)
}

// generateID kept for backward compatibility
func generateID() string {
    return generateSecureID("gen")
}
