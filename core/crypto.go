// core/crypto.go
package core

import (
    "strings"
	  
    "golang.org/x/crypto/bcrypt"
)

// HashPassword creates a bcrypt hash of the password
// bcrypt automatically handles salting
func HashPassword(password string) (string, error) {
    // bcrypt.DefaultCost is 10 - good balance of security and speed
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return "", err
    }
    return string(hash), nil
}

// CheckPassword compares a password with its hash
// Returns nil if they match, error otherwise
func CheckPassword(password, hash string) error {
    return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// IsBcryptHash checks if a string looks like a bcrypt hash
// Useful for migrating existing users
func IsBcryptHash(s string) bool {
    // bcrypt hashes start with $2a$, $2b$, or $2y$ and are 60 chars
    if len(s) != 60 {
        return false
    }
    return strings.HasPrefix(s, "$2a$") || 
           strings.HasPrefix(s, "$2b$") || 
           strings.HasPrefix(s, "$2y$")
}
