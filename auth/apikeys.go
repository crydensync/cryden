package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/token"
)

// apiKeyFragmentLength is how much of the secret goes into the
// non-secret Prefix — enough that a list of keys is distinguishable in
// a UI ("ck_9f3a1c02" vs "ck_be77d410"), and 32 fewer bits of secret
// than the 256 the generator produced, which changes nothing.
const apiKeyFragmentLength = 8

// apiKeyLastUsedGranularity is how stale LastUsedAt is allowed to get
// before AuthenticateAPIKey writes it again. A machine credential is
// presented on every request, and a store write per request would make
// the busiest path in the engine also the one that writes most. The
// field answers "is this key still in use", which five minutes of
// resolution answers just as well as five milliseconds would.
const apiKeyLastUsedGranularity = 5 * time.Minute

var (
	// ErrInvalidAPIKey covers every reason a presented key does not
	// authenticate: no such key, revoked, expired, malformed, empty.
	// One error for all of them on purpose — a caller able to tell
	// "never existed" from "revoked last week" can probe which of the
	// keys it stole are still live.
	ErrInvalidAPIKey = errors.New("auth: invalid, revoked or expired API key")

	// ErrAPIKeyNotFound is returned by RevokeAPIKey when the key does
	// not exist, is already revoked, or belongs to another user — the
	// same three-way silence, for the same reason.
	ErrAPIKeyNotFound = errors.New("auth: no such API key")

	// ErrInvalidAPIKeyScope rejects a scope the engine can be sure is a
	// mistake. Scopes are otherwise opaque host strings.
	ErrInvalidAPIKeyScope = errors.New("auth: invalid API key scope")

	// ErrInvalidAPIKeyTTL rejects a negative lifetime, which would mint
	// a key that has already expired. Zero means "never expires".
	ErrInvalidAPIKeyTTL = errors.New("auth: API key TTL cannot be negative")
)

// APIKeyIdentity is what a valid key resolves to: the account it acts
// as, and what it was permitted to do. It is deliberately not a
// session and not a set of tokens — nothing here is refreshed, revoked
// by logout, or countable in ListSessions. A machine holding a key is
// authenticated on every request from scratch.
type APIKeyIdentity struct {
	// UserID is the account the key authenticates as. Everything the
	// host authorises off a logged-in user applies to this ID too.
	UserID string
	// KeyID is the store row, for revocation and for the host's own
	// logging: it identifies which of the user's keys made the call
	// without the raw secret appearing in a log line.
	KeyID string
	// Name is the label the key was created with, presentational only.
	Name string
	// Scopes are the host-defined strings the key was granted. The
	// engine has never interpreted them and does not start here — see
	// HasScope, which is a convenience, not an authorisation decision.
	Scopes []string
}

// HasScope reports whether the key carries scope exactly. Exact string
// equality: no hierarchy, no wildcards, no "repo implies repo:read".
// A host wanting those owns the meaning of its own scope strings and
// should implement the comparison it means.
func (i APIKeyIdentity) HasScope(scope string) bool {
	for _, s := range i.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// GenerateAPIKey mints one machine-to-machine credential for an
// already-authenticated user and returns the raw key exactly once —
// the store only ever holds its SHA-256 hash, so nothing can display
// it again afterward. Same one-time-display contract as
// GenerateRecoveryCodes.
//
// ttl of 0 means the key never expires, which is the honest default
// for a credential that lives in a deploy pipeline's environment.
// Expiry is a convenience for hosts that want rotation; revocation is
// the mechanism that actually stops a key.
//
// The returned store.APIKey is the stored record with KeyHash cleared,
// for a host that wants to show the caller what it just created.
func GenerateAPIKey(
	ctx context.Context,
	users store.UserStore,
	keys store.APIKeyStore,
	ids security.IDGenerator,
	gen token.TokenGenerator,
	audit store.AuditStore,
	log logger.Logger,
	userID string,
	name string,
	scopes []string,
	ttl time.Duration,
	keyPrefix string,
) (string, store.APIKey, error) {
	if ttl < 0 {
		return "", store.APIKey{}, ErrInvalidAPIKeyTTL
	}
	for _, scope := range scopes {
		// An empty scope would silently satisfy HasScope(""), and a
		// scope with a space in it is a host that passed "read write"
		// as one element rather than two.
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") {
			return "", store.APIKey{}, fmt.Errorf("%w: %q", ErrInvalidAPIKeyScope, scope)
		}
	}

	// Checked so that every backend answers the same way: Postgres has
	// a foreign key here and would fail with a driver-specific error,
	// the in-memory store would happily create a key belonging to
	// nobody.
	if _, err := users.GetByID(ctx, userID); err != nil {
		return "", store.APIKey{}, err
	}

	secret, err := gen.New()
	if err != nil {
		return "", store.APIKey{}, err
	}
	keyID, err := ids.New()
	if err != nil {
		return "", store.APIKey{}, err
	}

	raw := keyPrefix + "_" + secret
	record := store.APIKey{
		ID:        keyID,
		UserID:    userID,
		Name:      name,
		Prefix:    apiKeyPrefixFragment(raw),
		KeyHash:   token.HashToken(raw),
		Scopes:    scopes,
		CreatedAt: time.Now(),
	}
	if ttl > 0 {
		expiresAt := record.CreatedAt.Add(ttl)
		record.ExpiresAt = &expiresAt
	}

	if err := keys.Create(ctx, record); err != nil {
		return "", store.APIKey{}, err
	}

	if err := audit.Record(ctx, store.AuditEvent{
		Type:   store.EventAPIKeyCreated,
		UserID: userID,
		Metadata: map[string]string{
			"key_id": record.ID,
			"prefix": record.Prefix,
			"scopes": strings.Join(scopes, " "),
		},
	}); err != nil {
		log.Error("generate api key: audit record failed", map[string]string{"error": err.Error(), "user_id": userID, "key_id": record.ID})
	}

	log.Info("api key created", map[string]string{"user_id": userID, "key_id": record.ID, "prefix": record.Prefix})

	record.KeyHash = ""
	return raw, record, nil
}

// apiKeyPrefixFragment takes the label plus the first few characters of
// the secret. Derived from the raw key rather than stored separately so
// the two can never disagree.
func apiKeyPrefixFragment(raw string) string {
	label, secret, found := strings.Cut(raw, "_")
	if !found {
		secret = raw
		label = ""
	}
	if len(secret) > apiKeyFragmentLength {
		secret = secret[:apiKeyFragmentLength]
	}
	if label == "" {
		return secret
	}
	return label + "_" + secret
}

// AuthenticateAPIKey resolves a presented raw key to the account and
// scopes it belongs to. This is the whole M2M login path: one indexed
// read on the key's hash, no session written, no tokens issued, no
// second factor — there is no human at the other end to prompt, and a
// key that resolved and then paused for a code would simply hang.
//
// It deliberately consults nothing but the APIKeyStore. In particular
// it does not check account lockout: lockout is driven by failed
// password attempts, so honouring it here would let anyone who knows a
// developer's email address take down that account's production
// integrations by failing to log in as them a few times. Revoking the
// key is the way to stop the key.
//
// Failures are ErrInvalidAPIKey and nothing more specific, whatever
// went wrong.
func AuthenticateAPIKey(
	ctx context.Context,
	keys store.APIKeyStore,
	audit store.AuditStore,
	log logger.Logger,
	rawKey string,
) (APIKeyIdentity, error) {
	// Trimmed because a key travels through environment variables and
	// header parsers, and a trailing newline is not a different
	// credential. The generated key contains no whitespace itself.
	raw := strings.TrimSpace(rawKey)
	if raw == "" {
		return APIKeyIdentity{}, ErrInvalidAPIKey
	}

	key, err := keys.GetByKeyHash(ctx, token.HashToken(raw))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// No audit event, on purpose. An unrecognised key is
			// unauthenticated traffic from anywhere on the internet,
			// and recording it would turn this into a write endpoint
			// into the audit table for anyone with a loop and a
			// wordlist. The host's own request log is where that
			// belongs, with the rate limiting to match.
			return APIKeyIdentity{}, ErrInvalidAPIKey
		}
		return APIKeyIdentity{}, err
	}

	now := time.Now()
	switch {
	case key.RevokedAt != nil:
		// Checked before expiry: a key that was revoked and has since
		// also passed its expiry reports the fact somebody acted on.
		rejectAPIKey(ctx, audit, log, key, "revoked")
		return APIKeyIdentity{}, ErrInvalidAPIKey
	case key.ExpiresAt != nil && !now.Before(*key.ExpiresAt):
		rejectAPIKey(ctx, audit, log, key, "expired")
		return APIKeyIdentity{}, ErrInvalidAPIKey
	}

	if key.LastUsedAt == nil || now.Sub(*key.LastUsedAt) >= apiKeyLastUsedGranularity {
		if err := keys.TouchLastUsed(ctx, key.ID, now); err != nil {
			// Best-effort by contract. A failure here means the "last
			// used" column is stale, not that the caller is
			// unauthenticated — failing the request over it would take
			// a working integration down to keep a timestamp tidy.
			log.Error("authenticate api key: touch last used failed", map[string]string{"error": err.Error(), "key_id": key.ID})
		}
	}

	return APIKeyIdentity{
		UserID: key.UserID,
		KeyID:  key.ID,
		Name:   key.Name,
		Scopes: key.Scopes,
	}, nil
}

// rejectAPIKey audits a key that exists but is no longer usable. Worth
// recording, unlike an unknown key: only somebody who once held a real
// credential for this account can trigger it, and "the CI key you
// revoked is still being presented every minute" is something its
// owner wants to know.
func rejectAPIKey(ctx context.Context, audit store.AuditStore, log logger.Logger, key store.APIKey, reason string) {
	if err := audit.Record(ctx, store.AuditEvent{
		Type:     store.EventAPIKeyRejected,
		UserID:   key.UserID,
		Metadata: map[string]string{"key_id": key.ID, "reason": reason},
	}); err != nil {
		log.Error("authenticate api key: audit record failed", map[string]string{"error": err.Error(), "key_id": key.ID, "reason": reason})
	}
	log.Warn("api key rejected", map[string]string{"key_id": key.ID, "user_id": key.UserID, "reason": reason})
}

// ListAPIKeys returns the user's live keys, newest first, so a host can
// build the "your API keys" screen that revocation needs — RevokeAPIKey
// takes a key ID, and this is the only place a host can learn one after
// creation.
//
// Revoked keys are excluded; expired-but-unrevoked ones are included,
// because "expired last Tuesday" is the answer to why a pipeline
// broke. KeyHash is cleared on every record: the host has no use for
// it, and the obvious implementation of that screen marshals whatever
// it is handed straight into a JSON response.
func ListAPIKeys(ctx context.Context, keys store.APIKeyStore, userID string) ([]store.APIKey, error) {
	records, err := keys.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	for i := range records {
		records[i].KeyHash = ""
	}
	return records, nil
}

// RevokeAPIKey permanently stops one of the user's keys. Irreversible
// by design: there is no un-revoke, because the reason a key gets
// revoked is that somebody else may have it. Mint a new one.
//
// Scoped to userID, so one account can never revoke another's key.
// Returns ErrAPIKeyNotFound for a key that does not exist, is already
// revoked, or belongs to somebody else.
func RevokeAPIKey(
	ctx context.Context,
	keys store.APIKeyStore,
	audit store.AuditStore,
	log logger.Logger,
	userID string,
	keyID string,
) error {
	if err := keys.Revoke(ctx, userID, keyID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrAPIKeyNotFound
		}
		return err
	}

	if err := audit.Record(ctx, store.AuditEvent{
		Type:     store.EventAPIKeyRevoked,
		UserID:   userID,
		Metadata: map[string]string{"key_id": keyID},
	}); err != nil {
		log.Error("revoke api key: audit record failed", map[string]string{"error": err.Error(), "user_id": userID, "key_id": keyID})
	}

	log.Info("api key revoked", map[string]string{"user_id": userID, "key_id": keyID})
	return nil
}
