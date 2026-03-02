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

// Session represents a user Session
type Session struct {
	ID           string
	UserID       string
	RefreshToken string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ExpiresAt    time.Time
}

// contains access and refresh tokens for a user
type TokenPair struct {
	AccessToken  string `json: "access_token"`
	RefreshToken string `json: "refresh_token"`
	TokenType    string `json: "token_type"`
	ExpiresIn    int64  `json: "expires_in"`
}

// Claims represents JWT claims
type Claims struct {
	UserID string `json: "user_id"`
	jwt.RegisteredClaims
}


