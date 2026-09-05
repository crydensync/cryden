package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// APIKeyStore is the production store.APIKeyStore implementation.
type APIKeyStore struct {
	db *sql.DB
}

func NewAPIKeyStore(db *sql.DB) *APIKeyStore {
	return &APIKeyStore{db: db}
}

// Create inserts the key. created_at is COALESCEd rather than left to
// the column default so that one clock decides both it and expires_at:
// the caller has already computed the expiry from its own now(), and
// letting the database stamp only the other half is how a row ends up
// claiming it expired before it was created.
func (s *APIKeyStore) Create(ctx context.Context, key store.APIKey) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO api_keys (id, user_id, name, prefix, key_hash, scopes, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, now()))
	`, key.ID, key.UserID, key.Name, key.Prefix, key.KeyHash,
		marshalScopes(key.Scopes), nullTime(key.ExpiresAt), nullTime(&key.CreatedAt))
	return err
}

const apiKeyColumns = `id, user_id, name, prefix, key_hash, scopes, expires_at, created_at, last_used_at, revoked_at`

func (s *APIKeyStore) GetByKeyHash(ctx context.Context, keyHash string) (store.APIKey, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT `+apiKeyColumns+` FROM api_keys WHERE key_hash = $1
	`, keyHash)
	key, err := scanAPIKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return store.APIKey{}, store.ErrNotFound
	}
	return key, err
}

func (s *APIKeyStore) ListByUser(ctx context.Context, userID string) ([]store.APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+apiKeyColumns+` FROM api_keys
		WHERE user_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC
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

func (s *APIKeyStore) Revoke(ctx context.Context, userID, keyID string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE api_keys SET revoked_at = now()
		WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
	`, keyID, userID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

// TouchLastUsed deliberately does not check rows affected: a key revoked
// between the read and this write matches nothing, and the interface
// documents that as acceptable rather than as a failed request.
func (s *APIKeyStore) TouchLastUsed(ctx context.Context, keyID string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE api_keys SET last_used_at = $1 WHERE id = $2
	`, at, keyID)
	return err
}

// scanner is what QueryRow and Query's rows have in common — enough to
// let one scan function serve both, since the column list is shared.
type scanner interface {
	Scan(dest ...any) error
}

func scanAPIKey(row scanner) (store.APIKey, error) {
	var key store.APIKey
	var name, prefix sql.NullString
	var scopes []byte
	var expiresAt, lastUsedAt, revokedAt sql.NullTime

	if err := row.Scan(&key.ID, &key.UserID, &name, &prefix, &key.KeyHash,
		&scopes, &expiresAt, &key.CreatedAt, &lastUsedAt, &revokedAt); err != nil {
		return store.APIKey{}, err
	}

	key.Name = name.String
	key.Prefix = prefix.String
	unmarshalled, err := unmarshalScopes(scopes)
	if err != nil {
		return store.APIKey{}, err
	}
	key.Scopes = unmarshalled
	if expiresAt.Valid {
		key.ExpiresAt = &expiresAt.Time
	}
	if lastUsedAt.Valid {
		key.LastUsedAt = &lastUsedAt.Time
	}
	if revokedAt.Valid {
		key.RevokedAt = &revokedAt.Time
	}
	return key, nil
}

// marshalScopes renders the scope list for the JSONB column, mapping a
// nil slice to SQL NULL. Returned as []byte, which lib/pq sends
// verbatim as text for any column type other than bytea — the same way
// AuditStore.Record writes its metadata.
func marshalScopes(scopes []string) []byte {
	if scopes == nil {
		return nil
	}
	b, err := json.Marshal(scopes)
	if err != nil {
		// Unreachable: []string always marshals.
		return nil
	}
	return b
}

func unmarshalScopes(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var scopes []string
	if err := json.Unmarshal(raw, &scopes); err != nil {
		return nil, err
	}
	return scopes, nil
}

// nullTime maps a nil or zero *time.Time to SQL NULL. Zero counts as
// absent because a caller that left CreatedAt alone means "you decide",
// not "the first instant of year 1".
func nullTime(t *time.Time) sql.NullTime {
	if t == nil || t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

var _ store.APIKeyStore = (*APIKeyStore)(nil)
