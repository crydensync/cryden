package security

import (
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// bcrypt at its minimum cost: these tests care which algorithm was used,
// never how expensive it was.
func testBcrypt(t *testing.T) *BcryptHasher {
	t.Helper()
	h, err := NewBcryptHasher(bcrypt.MinCost)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return h
}

func TestIdentifyHash(t *testing.T) {
	// The four bcrypt prefixes are all in the wild: $2a$ is what most
	// libraries have written for a decade, $2b$ is what x/crypto writes
	// now, and $2x$/$2y$ came out of the 2011 PHP sign-extension fix.
	cases := map[string]HashAlgorithm{
		"$2a$10$LN.f0Ax0dvXQwGgtDbabkeUQMTsZEBWaVGSFrjLwFbCOMXW/vHt/i": AlgorithmBcrypt,
		"$2b$04$LN.f0Ax0dvXQwGgtDbabkeUQMTsZEBWaVGSFrjLwFbCOMXW/vHt/i": AlgorithmBcrypt,
		"$2x$10$LN.f0Ax0dvXQwGgtDbabkeUQMTsZEBWaVGSFrjLwFbCOMXW/vHt/i": AlgorithmBcrypt,
		"$2y$10$LN.f0Ax0dvXQwGgtDbabkeUQMTsZEBWaVGSFrjLwFbCOMXW/vHt/i": AlgorithmBcrypt,
		"$argon2id$v=19$m=65536,t=3,p=4$c2FsdHlzYWx0$AAAAAAAAAAAAAAAA": AlgorithmArgon2id,
		// Neighbours that must not be mistaken for something this
		// package can verify.
		"$argon2i$v=19$m=65536,t=3,p=4$c2FsdHlzYWx0$AAAAAAAAAAAAAAAA": AlgorithmUnknown,
		"$argon2d$v=19$m=65536,t=3,p=4$c2FsdHlzYWx0$AAAAAAAAAAAAAAAA": AlgorithmUnknown,
		"$scrypt$ln=16,r=8,p=1$c2FsdHlzYWx0$AAAAAAAAAAAAAAAA":         AlgorithmUnknown,
		"$pbkdf2-sha256$29000$c2FsdHlzYWx0$AAAAAAAAAAAAAAAA":          AlgorithmUnknown,
		"$2$10$LN.f0Ax0dvXQwGgtDbabkeUQMTsZEBWaVGSFrjLwFbCOMXW/vHt/i": AlgorithmUnknown,
		"argon2id$v=19$m=65536,t=3,p=4$c2FsdHlzYWx0$AAAAAAAAAAAAAAAA": AlgorithmUnknown,
		"":        AlgorithmUnknown,
		"hunter2": AlgorithmUnknown,
	}
	for hash, want := range cases {
		if got := IdentifyHash(hash); got != want {
			t.Errorf("IdentifyHash(%q) = %q, want %q", hash, got, want)
		}
	}
}

func TestMultiHasher_HashUsesThePrimary(t *testing.T) {
	argon2id := NewMultiHasher(testArgon2id(t))
	hash, err := argon2id.Hash("Tr0ubl3-Fr33!2026")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := IdentifyHash(hash); got != AlgorithmArgon2id {
		t.Errorf("argon2id primary wrote a %q hash", got)
	}

	legacy := NewMultiHasher(testBcrypt(t))
	hash, err = legacy.Hash("Tr0ubl3-Fr33!2026")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := IdentifyHash(hash); got != AlgorithmBcrypt {
		t.Errorf("bcrypt primary wrote a %q hash", got)
	}
}

// The whole point of the type: verification is decided by the stored
// hash's own format, so which algorithm is configured today has no
// bearing on whether yesterday's hashes still work.
func TestMultiHasher_VerifiesBothAlgorithmsWhicheverIsPrimary(t *testing.T) {
	bcryptHash, err := testBcrypt(t).Hash("Tr0ubl3-Fr33!2026")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	argon2idHash, err := testArgon2id(t).Hash("Tr0ubl3-Fr33!2026")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for name, primary := range map[string]Hasher{
		"argon2id primary": testArgon2id(t),
		"bcrypt primary":   testBcrypt(t),
	} {
		t.Run(name, func(t *testing.T) {
			m := NewMultiHasher(primary)
			for algorithm, hash := range map[string]string{"bcrypt": bcryptHash, "argon2id": argon2idHash} {
				if err := m.Compare(hash, "Tr0ubl3-Fr33!2026"); err != nil {
					t.Errorf("%s hash did not verify: %v", algorithm, err)
				}
				if err := m.Compare(hash, "Tr0ubl3-Fr33!2025"); err == nil {
					t.Errorf("%s hash verified the wrong password", algorithm)
				}
			}
		})
	}
}

// recordingHasher is a host's own Hasher: it implements the interface and
// nothing else, which is the case the optional-interface design exists to
// keep working.
type recordingHasher struct {
	compared []string
	hashed   int
}

func (r *recordingHasher) Hash(string) (string, error) {
	r.hashed++
	return "$custom$whatever", nil
}

func (r *recordingHasher) Compare(hash, _ string) error {
	r.compared = append(r.compared, hash)
	return nil
}

// A format neither shipped hasher recognises belongs to the primary,
// which is the only thing that could have written it. Sending it to
// bcrypt instead would turn a working custom hasher into a login outage
// the moment MultiHasher was introduced.
func TestMultiHasher_UnknownFormatGoesToThePrimary(t *testing.T) {
	primary := &recordingHasher{}
	m := NewMultiHasher(primary)

	if err := m.Compare("$custom$whatever", "Tr0ubl3-Fr33!2026"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(primary.compared) != 1 || primary.compared[0] != "$custom$whatever" {
		t.Errorf("primary saw %v, want one call with the unknown hash", primary.compared)
	}

	// ...and a recognised format does not, even though the primary is the
	// only hasher configured.
	bcryptHash, _ := testBcrypt(t).Hash("Tr0ubl3-Fr33!2026")
	if err := m.Compare(bcryptHash, "Tr0ubl3-Fr33!2026"); err != nil {
		t.Errorf("bcrypt hash did not verify: %v", err)
	}
	if len(primary.compared) != 1 {
		t.Errorf("primary saw %d calls, want the bcrypt hash to have gone elsewhere", len(primary.compared))
	}
}

func TestMultiHasher_NeedsRehashDelegatesToThePrimary(t *testing.T) {
	bcryptHash, _ := testBcrypt(t).Hash("Tr0ubl3-Fr33!2026")
	argon2idHash, _ := testArgon2id(t).Hash("Tr0ubl3-Fr33!2026")

	m := NewMultiHasher(testArgon2id(t))
	if !m.NeedsRehash(bcryptHash) {
		t.Error("expected a bcrypt hash to be out of date under an argon2id primary")
	}
	if m.NeedsRehash(argon2idHash) {
		t.Error("expected an argon2id hash at the configured params to be left alone")
	}

	// A primary that only implements Hasher can still be asked, and the
	// answer is no: there is no way to know what it would want, and
	// rewriting hashes on a guess is worse than leaving them.
	if NewMultiHasher(&recordingHasher{}).NeedsRehash(bcryptHash) {
		t.Error("expected a primary that is not a Rehasher to never trigger an upgrade")
	}
}

// New() wraps whatever Config.Hasher holds, and a host can perfectly
// reasonably hand it a MultiHasher it built itself. Wrapping the wrapper
// would put a second dispatch layer in front of every login for nothing.
func TestNewMultiHasher_DoesNotNest(t *testing.T) {
	inner := NewMultiHasher(testArgon2id(t))
	if got := NewMultiHasher(inner); got != inner {
		t.Error("expected wrapping a MultiHasher to return it unchanged")
	}
	if _, ok := inner.Primary().(*Argon2idHasher); !ok {
		t.Errorf("Primary() is %T, want *Argon2idHasher", inner.Primary())
	}
}

// bcrypt truncates at 72 bytes and x/crypto reports that rather than
// silently ignoring the tail. The error has to reach the caller as an
// error — a hash written from a silently truncated password would verify
// against a different password than the user typed.
func TestMultiHasher_PropagatesAPrimaryHashError(t *testing.T) {
	m := NewMultiHasher(testBcrypt(t))
	long := make([]byte, 80)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := m.Hash(string(long)); !errors.Is(err, bcrypt.ErrPasswordTooLong) {
		t.Errorf("got %v, want bcrypt.ErrPasswordTooLong", err)
	}
}
