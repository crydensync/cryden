package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2idParams are the cost parameters an Argon2idHasher runs with.
// They are deployment tuning, exactly like bcrypt's cost: the right
// values depend on the hardware doing the hashing and the login latency
// you are willing to pay, so they are chosen by the host and not
// guessed at by the engine.
//
// Memory is in KiB (65536 = 64 MiB) and is what makes Argon2id worth
// having over bcrypt — it is the parameter a GPU or ASIC attacker
// cannot cheaply parallelize around.
type Argon2idParams struct {
	Memory      uint32 // KiB of memory per hash
	Iterations  uint32 // passes over that memory ("time cost")
	Parallelism uint8  // lanes, i.e. threads Argon2id may use
	SaltLength  uint32 // bytes of random salt per hash
	KeyLength   uint32 // bytes of derived key stored
}

// DefaultArgon2idParams is RFC 9106's second recommended option
// (64 MiB, t=3, p=4), which is the one that fits a login path on
// ordinary server hardware — the first (2 GiB, t=1) is aimed at
// key derivation where one call per boot is acceptable, not at
// something run on every sign-in.
//
// It sits comfortably above OWASP's stated floor of 19 MiB / t=2 / p=1.
// Raise Memory before Iterations if you have headroom: memory hardness
// is the whole reason to pick Argon2id.
var DefaultArgon2idParams = Argon2idParams{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

// maxArgon2idMemory caps Memory at 4 GiB, in KiB. This is a guard on
// the DECODE path as much as the constructor: Compare takes its
// parameters from the stored hash itself, so a corrupted or tampered
// m= value is otherwise an instruction to allocate that much memory
// during a login.
const maxArgon2idMemory = 4 * 1024 * 1024

// Argon2idHasher is the second Hasher implementation, alongside
// BcryptHasher. It is an addition, not a replacement: bcrypt hashes
// already in your users table keep verifying (see MultiHasher), and
// nothing in the engine assumes one algorithm.
//
// The encoded output is the standard PHC string,
//
//	$argon2id$v=19$m=65536,t=3,p=4$<salt>$<key>
//
// with both halves in unpadded standard base64. That format is the
// whole migration story: every parameter needed to verify a hash
// travels with the hash, so changing this hasher's configuration can
// never invalidate credentials written under the old one.
//
// Only argon2id is implemented. argon2i and argon2d are deliberately
// absent — RFC 9106 recommends id for password hashing, and accepting
// the other two would mean verifying hashes this engine would never
// choose to produce.
type Argon2idHasher struct {
	params Argon2idParams
}

var (
	_ Hasher   = (*Argon2idHasher)(nil)
	_ Rehasher = (*Argon2idHasher)(nil)
)

// NewArgon2idHasher constructs an Argon2idHasher. The entirely
// zero-valued struct means "use DefaultArgon2idParams", the same
// convention Config.PasswordPolicy and Config.AnomalyThresholds
// follow; setting even one field makes it a real custom configuration
// used as-is, so a partially filled struct is validated, not merged
// with the defaults.
func NewArgon2idHasher(params Argon2idParams) (*Argon2idHasher, error) {
	if params == (Argon2idParams{}) {
		params = DefaultArgon2idParams
	}
	if err := params.validate(); err != nil {
		return nil, err
	}
	return &Argon2idHasher{params: params}, nil
}

// Params returns the parameters new hashes are written with. The
// parameters an EXISTING hash was written with come from that hash,
// never from here.
func (a *Argon2idHasher) Params() Argon2idParams {
	return a.params
}

func (p Argon2idParams) validate() error {
	// Iterations and Parallelism below 1 panic inside
	// golang.org/x/crypto/argon2 rather than returning an error, so
	// they are rejected here instead.
	if p.Iterations < 1 || p.Parallelism < 1 {
		return ErrInvalidArgon2idParams
	}
	// argon2 rounds Memory down to a multiple of 4*Parallelism and
	// floors it at 8*Parallelism. Accepting less would record an m=
	// value in the hash that is not the memory actually used.
	if p.Memory < 8*uint32(p.Parallelism) || p.Memory > maxArgon2idMemory {
		return ErrInvalidArgon2idParams
	}
	// 8 bytes is the PHC minimum; 16 is the recommendation and the
	// default. KeyLength below 16 bytes is too short to be worth
	// storing at all.
	if p.SaltLength < 8 || p.KeyLength < 16 {
		return ErrInvalidArgon2idParams
	}
	return nil
}

func (a *Argon2idHasher) Hash(password string) (string, error) {
	salt := make([]byte, a.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("security: argon2id: reading salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt,
		a.params.Iterations, a.params.Memory, a.params.Parallelism, a.params.KeyLength)
	return encodeArgon2idHash(a.params, salt, key), nil
}

// Compare re-derives the key using the parameters stored IN hash, not
// this hasher's own. That is what lets one hasher verify credentials
// written years earlier under different costs — and it is why raising
// the parameters is safe to do at any time.
func (a *Argon2idHasher) Compare(hash, password string) error {
	params, salt, want, err := decodeArgon2idHash(hash)
	if err != nil {
		return err
	}
	got := argon2.IDKey([]byte(password), salt,
		params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

// NeedsRehash reports whether hash should be rewritten the next time
// the plaintext password is available — because it is not Argon2id at
// all, or because it is weaker than what this hasher now writes.
//
// "Weaker", not "different": a hash already stronger than the current
// configuration is left alone rather than downgraded. Parallelism is
// ignored entirely, since it is a throughput knob shaped by the
// hardware rather than a strength one, and treating a lane count change
// as a downgrade would churn every stored hash in the database for it.
func (a *Argon2idHasher) NeedsRehash(hash string) bool {
	params, _, _, err := decodeArgon2idHash(hash)
	if err != nil {
		return true
	}
	return params.Memory < a.params.Memory ||
		params.Iterations < a.params.Iterations ||
		params.SaltLength < a.params.SaltLength ||
		params.KeyLength < a.params.KeyLength
}

func encodeArgon2idHash(params Argon2idParams, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$%s$%s$%s",
		argon2.Version,
		encodeArgon2idParams(params),
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

func encodeArgon2idParams(params Argon2idParams) string {
	return fmt.Sprintf("m=%d,t=%d,p=%d", params.Memory, params.Iterations, params.Parallelism)
}

// decodeArgon2idHash parses a PHC-format argon2id string. SaltLength
// and KeyLength in the returned params are the observed lengths — the
// format does not carry them, and it does not need to.
func decodeArgon2idHash(hash string) (Argon2idParams, []byte, []byte, error) {
	var none Argon2idParams

	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return none, nil, nil, ErrMalformedHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return none, nil, nil, ErrMalformedHash
	}
	if version != argon2.Version {
		return none, nil, nil, ErrUnsupportedHashVersion
	}

	var params Argon2idParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d",
		&params.Memory, &params.Iterations, &params.Parallelism); err != nil {
		return none, nil, nil, ErrMalformedHash
	}
	// Sscanf stops as soon as the format is satisfied, so it accepts
	// trailing junk and leading zeros. Round-tripping the parse rejects
	// both: this segment must be exactly what this package would write.
	if encodeArgon2idParams(params) != parts[3] {
		return none, nil, nil, ErrMalformedHash
	}
	// The same panic guard as validate(), applied to values that came
	// from storage rather than from a caller.
	if params.Iterations < 1 || params.Parallelism < 1 || params.Memory > maxArgon2idMemory {
		return none, nil, nil, ErrMalformedHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return none, nil, nil, ErrMalformedHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return none, nil, nil, ErrMalformedHash
	}

	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(key))
	return params, salt, key, nil
}
