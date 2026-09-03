package postgres

import (
	"context"
	"database/sql"

	"github.com/crydensync/cryden/v2/store"
)

// WebAuthnStore is the v2 production store.WebAuthnCredentialStore
// implementation.
type WebAuthnStore struct {
	db *sql.DB
}

func NewWebAuthnStore(db *sql.DB) *WebAuthnStore {
	return &WebAuthnStore{db: db}
}

func (s *WebAuthnStore) Add(ctx context.Context, cred store.WebAuthnCredential) error {
	// credential_data is cast to string, not passed as raw []byte —
	// lib/pq sends a []byte argument as bytea on the wire, which
	// Postgres won't implicitly cast into a jsonb column. A string
	// argument is sent as text, which jsonb's input parser reads
	// correctly.
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO webauthn_credentials (id, user_id, credential_id, credential_data, nickname)
		VALUES ($1, $2, $3, $4, $5)
	`, cred.ID, cred.UserID, cred.CredentialID, string(cred.CredentialData), cred.Nickname)
	return err
}

func (s *WebAuthnStore) ListByUser(ctx context.Context, userID string) ([]store.WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, credential_id, credential_data, nickname, created_at, last_used_at
		FROM webauthn_credentials WHERE user_id = $1
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.WebAuthnCredential
	for rows.Next() {
		var c store.WebAuthnCredential
		var lastUsedAt sql.NullTime
		if err := rows.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.CredentialData, &c.Nickname, &c.CreatedAt, &lastUsedAt); err != nil {
			return nil, err
		}
		if lastUsedAt.Valid {
			c.LastUsedAt = &lastUsedAt.Time
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *WebAuthnStore) Update(ctx context.Context, cred store.WebAuthnCredential) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE webauthn_credentials
		SET credential_data = $2, last_used_at = now()
		WHERE credential_id = $1
	`, cred.CredentialID, string(cred.CredentialData))
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (s *WebAuthnStore) Delete(ctx context.Context, userID string, credentialID []byte) error {
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM webauthn_credentials WHERE user_id = $1 AND credential_id = $2
	`, userID, credentialID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

var _ store.WebAuthnCredentialStore = (*WebAuthnStore)(nil)
