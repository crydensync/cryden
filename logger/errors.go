package logger

import "errors"

var (
	// ErrUnknownLevel is reported by ParseLevel, which a host calls
	// directly on a configured string — there is no
	// Config.applyDefaults between an env var and it to turn a typo into
	// something sane.
	ErrUnknownLevel = errors.New("logger: unrecognized level name")

	// ErrMissingHashKey is reported by NewHashingRedactor. A redactor
	// that hashed with an empty key would still produce
	// correlatable-looking output while being trivially reversible for
	// the small value spaces that matter most here — the whole IPv4
	// space is 2^32 entries, which is an afternoon of precomputation.
	ErrMissingHashKey = errors.New("logger: hashing redactor requires a non-empty key")
)
