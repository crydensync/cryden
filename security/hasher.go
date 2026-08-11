package security

import "golang.org/x/crypto/bcrypt"

// Hasher defines password hashing operations. v1 ships one implementation:
// BcryptHasher. Compare must run in constant time relative to a correct
// vs incorrect password — bcrypt's ComparePassword already guarantees this.
type Hasher interface {
	Hash(password string) (string, error)
	Compare(hash, password string) error
}

// BcryptHasher is the v2 Hasher implementation.
type BcryptHasher struct {
	// Cost is the bcrypt work factor. Must be set explicitly by the
	// caller via Config — no silent default to a weak cost.
	Cost int
}

// NewBcryptHasher constructs a BcryptHasher. cost must be within
// bcrypt's valid range (bcrypt.MinCost..bcrypt.MaxCost); callers should
// use bcrypt.DefaultCost (10) as their own explicit choice, not rely on
// this constructor picking one for them.
func NewBcryptHasher(cost int) (*BcryptHasher, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return nil, ErrInvalidBcryptCost
	}
	return &BcryptHasher{Cost: cost}, nil
}

func (b *BcryptHasher) Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), b.Cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func (b *BcryptHasher) Compare(hash, password string) error {
	// bcrypt.CompareHashAndPassword is constant-time with respect to
	// the password comparison itself.
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
