package core

import "golang.org/x/crypto/bcrypt"

// Hasher defines password opperation
type Hasher interface {
	Hash(password string) (string, error)
	Compare(password, hash string) error
}

// BcryptHasher implement Hasher using bcrypt 
type BcryptHasher struct {
	Cost int
}

func NewBcryptHasher(cost int) *BcryptHasher {
	if cost < 4 || cost > 31 {
		cost = 10
	}
	return &BcryptHasher{Cost: cost}
}

func (h *BcryptHasher) Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.Cost)
return string(hash), err
}

func (h *BcryptHasher) Compare(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return ErrInvalidCredentials
	}
	return nil
}

// MockHasher for fast tests
type MockHasher struct{}

func (h *MockHasher) Hash(password string) (string, error) {
	return password, nil
}

func (h *MockHasher) Compare(password, hash string) error {
 if password == hash {
    return nil
 }
 return ErrInvalidCredentials
}
