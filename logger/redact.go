package logger

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// RedactedMarker replaces a sensitive value in a masking Redactor. The
// key itself stays in the record: a vendor's index and a host's own
// dashboards are built on the shape of these records, and a field that
// sometimes vanishes is harder to work with than one that is visibly
// masked.
const RedactedMarker = "[redacted]"

const (
	hashedPrefix    = "hmac-sha256:"
	hashedHexLength = 16
)

// DefaultRedactedKeys returns the field keys the engine itself can put a
// person's data under, which is the set a Redactor uses when given none:
//
//   - "ip" — the caller's address, on rate-limit, failed-login, anomaly
//     and credential-stuffing records. Personal data in its own right
//     under GDPR Art. 4, and the field most likely to matter to a
//     processor agreement.
//   - "user_id" — a UUIDv7 that means nothing without the users table,
//     but is still a stable per-person identifier, which is all a
//     pseudonymous identifier needs to be to count as one.
//   - "requesting_user_id" — the same thing under a different name, on
//     the OAuth link-rejected record. Listed explicitly because a
//     redactor that let a user ID through on account of a prefix would
//     be a redactor someone trusted.
//
// It is a function rather than a var because a package-level slice is
// mutable from anywhere, and the one thing a redaction default must not
// be is quietly editable by unrelated code.
//
// Notably absent: email addresses. The engine never logs one — the
// closest it comes is "magic link requested for unknown email", which
// carries only the IP. A host app logging its own records through the
// same Logger should pass its own keys in addition to these.
func DefaultRedactedKeys() []string {
	return []string{"ip", "user_id", "requesting_user_id"}
}

// Redactor replaces sensitive field values before they reach the Logger
// it wraps. It exists because of what shipping logs to a hosted
// aggregator actually changes: records that used to stay on a machine the
// host controls now sit in a third party's index, under that party's
// retention policy, reachable by whoever there can run a query.
//
// Two modes, both keeping the field key:
//
//   - Masking (NewMaskingRedactor) replaces the value with
//     RedactedMarker. Nothing survives.
//   - Hashing (NewHashingRedactor) replaces it with a keyed HMAC-SHA256
//     digest, so the same address still reads as the same address across
//     records — "one IP, forty accounts" stays visible in the sink, which
//     is exactly the shape credential stuffing has — while the address
//     itself does not leave. Keyed, not a bare hash: the entire IPv4
//     space is 2^32 values, so an unkeyed digest of an address is a
//     lookup table away from being the address.
//
// Messages are not scanned, only field values. The engine's messages are
// constant strings with every variable part in fields, so there is
// nothing there to find, and scanning free text for personal data is a
// heuristic this package will not pretend to be able to do reliably.
//
// A Redactor is a ContextLogger whatever it wraps, and forwards the
// context through — redacting must not cost the correlation the sink was
// bought for.
type Redactor struct {
	inner   Logger
	keys    map[string]struct{}
	hashKey []byte
}

// NewMaskingRedactor replaces the value of every listed key with
// RedactedMarker. With no keys given it uses DefaultRedactedKeys.
//
// Keys match case-insensitively. A redactor that leaked an address
// because the host wrote "IP" where the engine writes "ip" would be
// worse than useless — it would be a redactor someone trusted.
//
// A nil inner collapses to NopLogger, matching NewLevelFilter: a nil
// dereference inside a log statement would take down the call that was
// only trying to mention something.
func NewMaskingRedactor(inner Logger, keys ...string) *Redactor {
	return &Redactor{inner: orNop(inner), keys: keySet(keys)}
}

// NewHashingRedactor is NewMaskingRedactor with correlation kept:
// values are replaced by a keyed digest instead of a fixed marker.
//
// hashKey must be non-empty (ErrMissingHashKey otherwise) and must be
// the same on every replica, or one address hashes two ways and the
// correlation the mode exists for is gone. Give it a value of its own
// rather than reusing Config.EncryptionKey or Config.JWTSecret — key
// separation costs nothing here, and this one is handed to a component
// whose whole job is to hand its output to a third party.
func NewHashingRedactor(inner Logger, hashKey string, keys ...string) (*Redactor, error) {
	if hashKey == "" {
		return nil, ErrMissingHashKey
	}
	return &Redactor{
		inner:   orNop(inner),
		keys:    keySet(keys),
		hashKey: []byte(hashKey),
	}, nil
}

func (r *Redactor) Debug(msg string, fields map[string]string) {
	r.Log(context.Background(), LevelDebug, msg, fields)
}

func (r *Redactor) Info(msg string, fields map[string]string) {
	r.Log(context.Background(), LevelInfo, msg, fields)
}

func (r *Redactor) Warn(msg string, fields map[string]string) {
	r.Log(context.Background(), LevelWarn, msg, fields)
}

func (r *Redactor) Error(msg string, fields map[string]string) {
	r.Log(context.Background(), LevelError, msg, fields)
}

func (r *Redactor) Log(ctx context.Context, level Level, msg string, fields map[string]string) {
	if ctx == nil {
		ctx = context.Background()
	}
	emit(ctx, r.inner, level, msg, r.redact(fields))
}

var _ ContextLogger = (*Redactor)(nil)

// redact returns fields with every sensitive value replaced, copying the
// map only when there is something to replace. The caller's map is never
// modified: the same map may already have gone to a sink that is meant to
// see the real values, since the intended wiring puts this inside a
// MultiLogger beside a console logger that keeps them.
func (r *Redactor) redact(fields map[string]string) map[string]string {
	if len(fields) == 0 {
		return fields
	}
	var out map[string]string
	for key, value := range fields {
		// An empty value has nothing to hide, and a marker or a digest
		// standing in for it would suggest it did.
		if value == "" || !r.sensitive(key) {
			continue
		}
		if out == nil {
			out = make(map[string]string, len(fields))
			for k, v := range fields {
				out[k] = v
			}
		}
		out[key] = r.replace(value)
	}
	if out == nil {
		return fields
	}
	return out
}

func (r *Redactor) sensitive(key string) bool {
	_, ok := r.keys[strings.ToLower(key)]
	return ok
}

func (r *Redactor) replace(value string) string {
	if len(r.hashKey) == 0 {
		return RedactedMarker
	}
	mac := hmac.New(sha256.New, r.hashKey)
	mac.Write([]byte(value))
	// Truncated to 64 bits: enough that two different addresses colliding
	// is not something a host will see, short enough to read in a log
	// line, and one less bit of the digest to attack offline.
	return hashedPrefix + hex.EncodeToString(mac.Sum(nil))[:hashedHexLength]
}

func keySet(keys []string) map[string]struct{} {
	if len(keys) == 0 {
		keys = DefaultRedactedKeys()
	}
	set := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if key == "" {
			continue
		}
		set[strings.ToLower(key)] = struct{}{}
	}
	return set
}

func orNop(l Logger) Logger {
	if l == nil {
		return NewNopLogger()
	}
	return l
}
