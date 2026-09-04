package security

import "golang.org/x/crypto/bcrypt"

// Hasher defines password hashing operations. Two implementations ship:
// BcryptHasher and Argon2idHasher, and MultiHasher combines them so a
// users table holding both formats keeps working. Compare must run in
// constant time relative to a correct vs incorrect password — bcrypt's
// CompareHashAndPassword and Argon2idHasher's subtle-based comparison
// both guarantee this.
type Hasher interface {
	Hash(password string) (string, error)
	Compare(hash, password string) error
}

// Rehasher is an optional second capability a Hasher may implement: it
// reports that a stored hash is out of date — the wrong algorithm, or
// the right one at costs since raised — and should be rewritten the
// next time the plaintext password passes through.
//
// Deliberately NOT part of Hasher. A host that has written its own
// Hasher keeps compiling and simply never triggers an upgrade, which is
// the correct behaviour for an implementation the engine cannot reason
// about. Login type-asserts for this; nothing else in the engine does.
type Rehasher interface {
	NeedsRehash(hash string) bool
}

// BcryptHasher is the original Hasher implementation and still the
// default: an engine given no hasher of its own builds one from
// Config.BcryptCost.
type BcryptHasher struct {
	// Cost is the bcrypt work factor. Must be set explicitly by the
	// caller via Config — no silent default to a weak cost.
	Cost int
}

// NewBcryptHasher constructs a BcryptHasher. cost must be within
// bcrypt's valid range (bcrypt.MinCost..bcrypt.MaxCost); callers should
// use bcrypt.DefaultCost (10) as their own explicit choice, not rely on
// this constructor picking one for them.
var (
	_ Hasher   = (*BcryptHasher)(nil)
	_ Rehasher = (*BcryptHasher)(nil)
)

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

// NeedsRehash reports whether hash should be rewritten with this
// hasher's current cost. True for anything that is not bcrypt at all,
// and for a bcrypt hash written at a LOWER cost than is configured now
// — raising Cost is the ordinary reason this returns true.
//
// A hash written at a higher cost than configured is left alone. It is
// already stronger than what this hasher would write, and rewriting it
// would be a downgrade performed automatically, which is never what
// lowering a cost knob was meant to ask for.
func (b *BcryptHasher) NeedsRehash(hash string) bool {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		// Not a bcrypt hash (or not a readable one) — including every
		// Argon2id hash, which is exactly the case that makes migrating
		// TO bcrypt work as well as away from it.
		return true
	}
	return cost < b.Cost
}
