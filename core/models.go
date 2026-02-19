package core

import "time"

// User represents a user in the system
type User struct {
	ID            string
	Email         string
	PasswordHash  string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Session represents a user Session
type Session struct {
	ID            string
	UserID        string
	RefreshToken  string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	ExpiresAt     time.Time
}

// contains access and refresh tokens for a user
type TokenPair struct {
	AccessToken   string
	RefreshToken  string
}
