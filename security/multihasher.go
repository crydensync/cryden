package security

import "strings"

// HashAlgorithm names the algorithm that produced a stored hash. It is
// derived from the hash itself, never from configuration — see
// IdentifyHash.
type HashAlgorithm string

const (
	AlgorithmBcrypt   HashAlgorithm = "bcrypt"
	AlgorithmArgon2id HashAlgorithm = "argon2id"
	// AlgorithmUnknown covers anything this package cannot verify:
	// argon2i/argon2d, scrypt, PBKDF2, a format from whatever framework
	// the user table was imported from, or plain corruption.
	AlgorithmUnknown HashAlgorithm = "unknown"
)

// IdentifyHash sniffs a stored hash's own prefix. This is what makes a
// mixed users table workable at all: the alternative is a column
// recording which algorithm each row used, which means a migration, a
// backfill, and a value that can disagree with the hash sitting next to
// it. The hash already carries the answer — bcrypt has said $2a$/$2b$
// since 1999 and every PHC-format hash names its own algorithm.
//
// It never inspects the password and never verifies anything, so it is
// safe to log or record in an audit event.
func IdentifyHash(hash string) HashAlgorithm {
	switch {
	case strings.HasPrefix(hash, "$argon2id$"):
		return AlgorithmArgon2id
	// $2b$ is current, $2a$ is what most existing databases hold, and
	// $2y$/$2x$ come from PHP's crypt(). x/crypto/bcrypt verifies all
	// four, so all four are recognized here.
	case strings.HasPrefix(hash, "$2a$"),
		strings.HasPrefix(hash, "$2b$"),
		strings.HasPrefix(hash, "$2x$"),
		strings.HasPrefix(hash, "$2y$"):
		return AlgorithmBcrypt
	default:
		return AlgorithmUnknown
	}
}

// MultiHasher writes with one algorithm and verifies against every
// algorithm the engine knows. It is what the engine actually holds:
// New() wraps whichever primary hasher it ends up with in one of these,
// so switching Config.Hasher from bcrypt to Argon2id (or back) can
// never lock out an account whose hash predates the switch.
//
// Verification needs no configuration of its own, which is what makes
// this cheap: bcrypt embeds its cost in the hash and a PHC string
// carries m, t, p and the salt, so the parameters a stored hash was
// written with always travel with it. The primary hasher is consulted
// for Hash — and for a hash in a format this package does not
// recognize, since a custom Hasher is the only thing that could know
// its own format.
type MultiHasher struct {
	primary Hasher

	// Verification-only instances. Their own parameters are never used
	// — Compare reads everything it needs from the hash — so they are
	// deliberately built without any.
	bcrypt   *BcryptHasher
	argon2id *Argon2idHasher
}

var (
	_ Hasher   = (*MultiHasher)(nil)
	_ Rehasher = (*MultiHasher)(nil)
)

// NewMultiHasher wraps primary. Passing an existing *MultiHasher back
// in is allowed and returns it unchanged rather than nesting, so a host
// that assembles its own does not end up with two layers of dispatch.
func NewMultiHasher(primary Hasher) *MultiHasher {
	if m, ok := primary.(*MultiHasher); ok {
		return m
	}
	return &MultiHasher{
		primary:  primary,
		bcrypt:   &BcryptHasher{},
		argon2id: &Argon2idHasher{},
	}
}

// Primary returns the hasher new passwords are written with.
func (m *MultiHasher) Primary() Hasher {
	return m.primary
}

// Hash always uses the primary hasher. Nothing here ever writes a hash
// in an algorithm the host did not configure.
func (m *MultiHasher) Hash(password string) (string, error) {
	return m.primary.Hash(password)
}

// Compare routes on the stored hash's format. A recognized format is
// verified by this package's own implementation for it, whatever the
// primary happens to be — so a custom Hasher must not emit hashes
// prefixed $2a$/$2b$/$2x$/$2y$/$argon2id$ unless they really are those
// formats.
func (m *MultiHasher) Compare(hash, password string) error {
	switch IdentifyHash(hash) {
	case AlgorithmBcrypt:
		return m.bcrypt.Compare(hash, password)
	case AlgorithmArgon2id:
		return m.argon2id.Compare(hash, password)
	default:
		return m.primary.Compare(hash, password)
	}
}

// NeedsRehash defers entirely to the primary hasher, because "out of
// date" means "not what we would write now" and only the primary knows
// what that is. A primary that does not implement Rehasher never
// reports one.
func (m *MultiHasher) NeedsRehash(hash string) bool {
	rehasher, ok := m.primary.(Rehasher)
	if !ok {
		return false
	}
	return rehasher.NeedsRehash(hash)
}
