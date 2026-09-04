package security

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// Deliberately far below DefaultArgon2idParams: these tests are about
// encoding, dispatch and validation, and 64 MiB per Hash call would make
// the suite slow without checking anything the small values don't.
var testParams = Argon2idParams{
	Memory:      64,
	Iterations:  1,
	Parallelism: 1,
	SaltLength:  8,
	KeyLength:   16,
}

func testArgon2id(t *testing.T) *Argon2idHasher {
	t.Helper()
	h, err := NewArgon2idHasher(testParams)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return h
}

func TestNewArgon2idHasher_ZeroParamsMeansDefaults(t *testing.T) {
	h, err := NewArgon2idHasher(Argon2idParams{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.Params() != DefaultArgon2idParams {
		t.Errorf("got %+v, want DefaultArgon2idParams %+v", h.Params(), DefaultArgon2idParams)
	}
}

func TestNewArgon2idHasher_RejectsInvalidParams(t *testing.T) {
	// A partially filled struct is a real configuration, so it is
	// validated rather than quietly completed from the defaults.
	cases := map[string]Argon2idParams{
		"no iterations":      {Memory: 64, Iterations: 0, Parallelism: 1, SaltLength: 8, KeyLength: 16},
		"no parallelism":     {Memory: 64, Iterations: 1, Parallelism: 0, SaltLength: 8, KeyLength: 16},
		"memory below 8*p":   {Memory: 16, Iterations: 1, Parallelism: 4, SaltLength: 8, KeyLength: 16},
		"memory above cap":   {Memory: maxArgon2idMemory + 1, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16},
		"salt too short":     {Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 7, KeyLength: 16},
		"key too short":      {Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 15},
		"only one field set": {Memory: 64},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewArgon2idHasher(params); !errors.Is(err, ErrInvalidArgon2idParams) {
				t.Errorf("got %v, want ErrInvalidArgon2idParams", err)
			}
		})
	}
}

func TestArgon2idHasher_HashAndCompare(t *testing.T) {
	h := testArgon2id(t)

	hash, err := h.Hash("Tr0ubl3-Fr33!2026")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}
	if strings.Contains(hash, "Tr0ubl3-Fr33!2026") {
		t.Fatal("the password must not appear in its own hash")
	}
	if err := h.Compare(hash, "Tr0ubl3-Fr33!2026"); err != nil {
		t.Errorf("expected the correct password to verify, got %v", err)
	}
	if err := h.Compare(hash, "Tr0ubl3-Fr33!2025"); !errors.Is(err, ErrPasswordMismatch) {
		t.Errorf("got %v, want ErrPasswordMismatch", err)
	}
}

func TestArgon2idHasher_SameInputDifferentHashes(t *testing.T) {
	h := testArgon2id(t)
	first, _ := h.Hash("Tr0ubl3-Fr33!2026")
	second, _ := h.Hash("Tr0ubl3-Fr33!2026")
	if first == second {
		t.Error("expected a fresh salt per hash, got two identical hashes")
	}
}

func TestArgon2idHasher_EncodesThePHCFormat(t *testing.T) {
	// The format is the migration story — every parameter a verifier
	// needs travels inside the hash — so its shape is worth pinning.
	h := testArgon2id(t)
	hash, _ := h.Hash("Tr0ubl3-Fr33!2026")

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Fatalf("got %d segments in %q, want 6", len(parts), hash)
	}
	if parts[1] != "argon2id" {
		t.Errorf("algorithm segment is %q, want argon2id", parts[1])
	}
	if parts[2] != "v=19" {
		t.Errorf("version segment is %q, want v=19", parts[2])
	}
	if parts[3] != "m=64,t=1,p=1" {
		t.Errorf("parameter segment is %q, want m=64,t=1,p=1", parts[3])
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatalf("salt is not unpadded standard base64: %v", err)
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		t.Fatalf("key is not unpadded standard base64: %v", err)
	}
	if len(salt) != int(testParams.SaltLength) || len(key) != int(testParams.KeyLength) {
		t.Errorf("got %d salt bytes and %d key bytes, want %d and %d",
			len(salt), len(key), testParams.SaltLength, testParams.KeyLength)
	}
}

func TestArgon2idHasher_VerifiesHashesWrittenWithOtherParams(t *testing.T) {
	// Raising the cost must never invalidate credentials written under
	// the old one. Compare reads m/t/p and the salt out of the hash, so
	// the hasher's own configuration is irrelevant to verification.
	weak := testArgon2id(t)
	hash, _ := weak.Hash("Tr0ubl3-Fr33!2026")

	strong, err := NewArgon2idHasher(Argon2idParams{
		Memory: 256, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := strong.Compare(hash, "Tr0ubl3-Fr33!2026"); err != nil {
		t.Errorf("expected the old hash to still verify, got %v", err)
	}
	if err := strong.Compare(hash, "wrong"); !errors.Is(err, ErrPasswordMismatch) {
		t.Errorf("got %v, want ErrPasswordMismatch", err)
	}
}

func TestArgon2idHasher_RejectsMalformedHashes(t *testing.T) {
	// Every one of these is something that could be sitting in a users
	// table — hand-edited, truncated by a column that was too narrow,
	// written by another library, or simply not Argon2id at all. None of
	// them may verify, and none may panic.
	h := testArgon2id(t)
	valid, _ := h.Hash("Tr0ubl3-Fr33!2026")

	malformed := map[string]string{
		"empty":                "",
		"not a hash at all":    "hunter2",
		"bcrypt":               "$2b$04$LN.f0Ax0dvXQwGgtDbabkeUQMTsZEBWaVGSFrjLwFbCOMXW/vHt/i",
		"argon2i not argon2id": strings.Replace(valid, "argon2id", "argon2i", 1),
		"too few segments":     "$argon2id$v=19$m=64,t=1,p=1$c2FsdHlzYWx0",
		"too many segments":    valid + "$extra",
		"no leading dollar":    strings.TrimPrefix(valid, "$"),
		"unreadable version":   strings.Replace(valid, "v=19", "v=nineteen", 1),
		"unreadable params":    strings.Replace(valid, "m=64,t=1,p=1", "m=sixty-four,t=1,p=1", 1),
		"missing a param":      strings.Replace(valid, "m=64,t=1,p=1", "m=64,t=1", 1),
		"trailing junk":        strings.Replace(valid, "m=64,t=1,p=1", "m=64,t=1,p=1,x=9", 1),
		"leading zeros":        strings.Replace(valid, "m=64,t=1,p=1", "m=064,t=1,p=1", 1),
		"zero iterations":      strings.Replace(valid, "m=64,t=1,p=1", "m=64,t=0,p=1", 1),
		"zero parallelism":     strings.Replace(valid, "m=64,t=1,p=1", "m=64,t=1,p=0", 1),
		"absurd memory":        strings.Replace(valid, "m=64,t=1,p=1", "m=4294967295,t=1,p=1", 1),
		"salt not base64":      "$argon2id$v=19$m=64,t=1,p=1$not!base64!$AAAAAAAAAAAAAAAAAAAAAA",
		"key not base64":       "$argon2id$v=19$m=64,t=1,p=1$c2FsdHlzYWx0$not!base64!",
		"empty salt and key":   "$argon2id$v=19$m=64,t=1,p=1$$",
	}
	for name, hash := range malformed {
		t.Run(name, func(t *testing.T) {
			if err := h.Compare(hash, "Tr0ubl3-Fr33!2026"); !errors.Is(err, ErrMalformedHash) {
				t.Errorf("got %v, want ErrMalformedHash", err)
			}
		})
	}
}

// A future Argon2id version is readable enough to name but not to
// verify against, and saying so is more useful to whoever is reading the
// logs than calling it malformed.
func TestArgon2idHasher_RejectsAnUnsupportedVersion(t *testing.T) {
	h := testArgon2id(t)
	valid, _ := h.Hash("Tr0ubl3-Fr33!2026")

	for _, v := range []string{"v=16", "v=20"} {
		hash := strings.Replace(valid, "v=19", v, 1)
		if err := h.Compare(hash, "Tr0ubl3-Fr33!2026"); !errors.Is(err, ErrUnsupportedHashVersion) {
			t.Errorf("%s: got %v, want ErrUnsupportedHashVersion", v, err)
		}
	}
}

// Flipping one byte of the derived key must read as a mismatch, not as a
// pass — the constant-time comparison is over the whole key.
func TestArgon2idHasher_RejectsATamperedKey(t *testing.T) {
	h := testArgon2id(t)
	valid, _ := h.Hash("Tr0ubl3-Fr33!2026")

	parts := strings.Split(valid, "$")
	key, _ := base64.RawStdEncoding.DecodeString(parts[5])
	key[0] ^= 0xff
	parts[5] = base64.RawStdEncoding.EncodeToString(key)

	if err := h.Compare(strings.Join(parts, "$"), "Tr0ubl3-Fr33!2026"); !errors.Is(err, ErrPasswordMismatch) {
		t.Errorf("got %v, want ErrPasswordMismatch", err)
	}
}

func TestArgon2idHasher_NeedsRehash(t *testing.T) {
	hashWith := func(t *testing.T, params Argon2idParams) string {
		t.Helper()
		h, err := NewArgon2idHasher(params)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		hash, err := h.Hash("Tr0ubl3-Fr33!2026")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return hash
	}

	strongerParams := Argon2idParams{Memory: 128, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}

	cases := []struct {
		name       string
		configured Argon2idParams
		stored     Argon2idParams
		want       bool
	}{
		{"identical params", testParams, testParams, false},
		{"stored memory is lower", Argon2idParams{Memory: 128, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16}, testParams, true},
		{"stored iterations are fewer", Argon2idParams{Memory: 64, Iterations: 2, Parallelism: 1, SaltLength: 8, KeyLength: 16}, testParams, true},
		{"stored salt is shorter", Argon2idParams{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16}, testParams, true},
		{"stored key is shorter", Argon2idParams{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 32}, testParams, true},
		// Stronger than configured is left alone: an upgrade is not a
		// reason to walk a hash back down to the current settings.
		{"stored params are stronger", testParams, strongerParams, false},
		// Parallelism is a throughput knob, not a strength one. Rehashing
		// on it would churn every stored hash the first time the service
		// moved to a machine with a different core count.
		{"only parallelism differs", Argon2idParams{Memory: 64, Iterations: 1, Parallelism: 2, SaltLength: 8, KeyLength: 16}, testParams, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := NewArgon2idHasher(tc.configured)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := h.NeedsRehash(hashWith(t, tc.stored)); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}

	// Anything this hasher cannot read is out of date by definition —
	// including every bcrypt hash, which is what drives a migration.
	h := testArgon2id(t)
	for _, hash := range []string{
		"",
		"$2b$04$LN.f0Ax0dvXQwGgtDbabkeUQMTsZEBWaVGSFrjLwFbCOMXW/vHt/i",
		"$argon2id$v=19$m=64,t=1,p=1$!!!!$!!!!",
	} {
		if !h.NeedsRehash(hash) {
			t.Errorf("expected NeedsRehash(%q) to be true", hash)
		}
	}
}
