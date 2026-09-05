package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// APIKeyStore is the SQLite implementation of store.APIKeyStore.
type APIKeyStore struct {
	db *sql.DB
}

// NewAPIKeyStore returns an APIKeyStore backed by an already-open
// database. The caller owns db's lifecycle.
func NewAPIKeyStore(db *sql.DB) *APIKeyStore {
	return &APIKeyStore{db: db}
}

// Create inserts the key, taking the caller's CreatedAt when it set one
// and its own clock otherwise. One clock decides both this and
// expires_at: the caller computed the expiry from its own now(), and
// stamping only the other half here is how a row ends up claiming it
// expired before it was created.
func (s *APIKeyStore) Create(ctx context.Context, key store.APIKey) error {
	createdAt := key.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	scopes, err := marshalScopes(key.Scopes)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO api_keys (id, user_id, name, prefix, key_hash, scopes, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, key.ID, key.UserID, key.Name, key.Prefix, key.KeyHash,
		scopes, formatTimePtr(key.ExpiresAt), formatTime(createdAt))
	return err
}

const apiKeyColumns = `id, user_id, name, prefix, key_hash, scopes, expires_at, created_at, last_used_at, revoked_at`

func (s *APIKeyStore) GetByKeyHash(ctx context.Context, keyHash string) (store.APIKey, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT `+apiKeyColumns+` FROM api_keys WHERE key_hash = ?
	`, keyHash)
	key, err := scanAPIKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return store.APIKey{}, store.ErrNotFound
	}
	return key, err
}

// ListByUser orders by created_at DESC, which is a text comparison on a
// TEXT column and works only because formatTime pads every value to the
// same width in UTC. id is the tiebreak: UUIDv7s sort by creation, so
// two keys minted in the same nanosecond still come back stably.
func (s *APIKeyStore) ListByUser(ctx context.Context, userID string) ([]store.APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+apiKeyColumns+` FROM api_keys
		WHERE user_id = ? AND revoked_at IS NULL
		ORDER BY created_at DESC, id DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.APIKey
	for rows.Next() {
		key, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, rows.Err()
}

// Revoke is scoped by user_id as well as id so that a key ID guessed or
// leaked from somewhere else cannot be revoked by the wrong account,
// and by revoked_at IS NULL so a second revocation reports not-found
// rather than silently moving the timestamp.
func (s *APIKeyStore) Revoke(ctx context.Context, userID, keyID string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE api_keys SET revoked_at = ?
		WHERE id = ? AND user_id = ? AND revoked_at IS NULL
	`, formatTime(time.Now()), keyID, userID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

// TouchLastUsed deliberately does not check rows affected: a key
// revoked between the read and this write matches nothing, and the
// interface documents that as acceptable rather than as a failed
// request.
func (s *APIKeyStore) TouchLastUsed(ctx context.Context, keyID string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE api_keys SET last_used_at = ? WHERE id = ?
	`, formatTime(at), keyID)
	return err
}

// scanner is what QueryRow and Query's rows have in common — enough to
// let one scan function serve both, since the column list is shared.
type scanner interface {
	Scan(dest ...any) error
}

func scanAPIKey(row scanner) (store.APIKey, error) {
	var key store.APIKey
	var name, prefix, scopes sql.NullString
	var expiresAt, createdAt, lastUsedAt, revokedAt scanTime

	if err := row.Scan(&key.ID, &key.UserID, &name, &prefix, &key.KeyHash,
		&scopes, &expiresAt, &createdAt, &lastUsedAt, &revokedAt); err != nil {
		return store.APIKey{}, err
	}

	key.Name = name.String
	key.Prefix = prefix.String
	if scopes.Valid {
		if err := json.Unmarshal([]byte(scopes.String), &key.Scopes); err != nil {
			return store.APIKey{}, err
		}
	}
	key.ExpiresAt = expiresAt.ptr()
	key.CreatedAt = createdAt.Time
	key.LastUsedAt = lastUsedAt.ptr()
	key.RevokedAt = revokedAt.ptr()
	return key, nil
}

// marshalScopes renders the scope list for the TEXT column that holds
// it as JSON, mapping a nil slice to SQL NULL. An empty non-nil slice
// stays "[]" — a host that asked for a key with no scopes gets one
// back with no scopes, not one whose scopes are unknown.
func marshalScopes(scopes []string) (sql.NullString, error) {
	if scopes == nil {
		return sql.NullString{}, nil
	}
	b, err := json.Marshal(scopes)
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: string(b), Valid: true}, nil
}

var _ store.APIKeyStore = (*APIKeyStore)(nil)
