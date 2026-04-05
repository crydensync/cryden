package core

import (
    "time"
    "github.com/golang-jwt/jwt/v5"
)

// User represents a user in the system
type User struct {
    ID           string
    Email        string
    PasswordHash string
    CreatedAt    time.Time
    UpdatedAt    time.Time
}

// Session represents a user session
type Session struct {
    ID           string    `json:"id"`
    UserID       string    `json:"user_id"`
    RefreshToken string    `json:"refresh_token"`
    LookupHash   string    `json:"-"`
    CreatedAt    time.Time `json:"created_at"`
    ExpiresAt    time.Time `json:"expires_at"`
    LastSeenAt   time.Time `json:"last_seen_at"`
    IPAddress    string    `json:"ip_address,omitempty"`
    DeviceName   string    `json:"device_name,omitempty"`
    DeviceType   string    `json:"device_type,omitempty"`
    Browser      string    `json:"browser,omitempty"`
    OS           string    `json:"os,omitempty"`
    Location     string    `json:"location,omitempty"`
}

/*
// Session represents a user session with hashed refresh token
type Session struct {
    ID           string
    UserID       string
    RefreshToken string // bcrypt hash of refresh token (stored)
    LookupHash   string // SHA256 hash for fast DB lookup (indexed)
    CreatedAt    time.Time
    ExpiresAt    time.Time
}
*/

// TokenPair contains access and refresh tokens
type TokenPair struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"` // Plain text token sent to client
    TokenType    string `json:"token_type"`
    ExpiresIn    int64  `json:"expires_in"`
}

// Claims represents JWT claims
type Claims struct {
    UserID string `json:"user_id"`
    jwt.RegisteredClaims
}
