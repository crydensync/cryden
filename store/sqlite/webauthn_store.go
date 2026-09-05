package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// WebAuthnStore is the SQLite implementation of
// store.WebAuthnCredentialStore.
type WebAuthnStore struct {
	db *sql.DB
}

// NewWebAuthnStore returns a WebAuthnStore backed by an already-open
// database. The caller owns db's lifecycle.
func NewWebAuthnStore(db *sql.DB) *WebAuthnStore {
	return &WebAuthnStore{db: db}
}

// Add registers a new passkey.
//
// CredentialID goes in as raw []byte — the column is BLOB, and a
// passkey ID is not text. CredentialData is converted to string
// because it is JSON and the column is TEXT: passing it as []byte
// would store a blob whose contents happen to be JSON, which SQLite's
// own json_* functions will not read.
//
// The Postgres implementation converts the same field for a related but
// different reason (lib/pq sends []byte as bytea, which does not
// implicitly cast to jsonb). Same conversion, two backends, two
// different underlying causes.
func (s *WebAuthnStore) Add(ctx context.Context, cred store.WebAuthnCredential) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO webauthn_credentials (id, user_id, credential_id, credential_data, nickname, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, cred.ID, cred.UserID, cred.CredentialID, string(cred.CredentialData),
		cred.Nickname, formatTime(time.Now()))
	return err
}

// ListByUser returns the user's registered passkeys, oldest first.
//
// Postgres leaves this unordered. Neither backend promises an order, so
// no caller can depend on one, and registration order is the useful one
// for a list of devices — this adds a guarantee rather than changing an
// existing one.
func (s *WebAuthnStore) ListByUser(ctx context.Context, userID string) ([]store.WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, credential_id, credential_data, nickname, created_at, last_used_at
		FROM webauthn_credentials WHERE user_id = ?
		ORDER BY created_at ASC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.WebAuthnCredential
	for rows.Next() {
		var (
			cred       store.WebAuthnCredential
			data       string
			createdAt  scanTime
			lastUsedAt scanTime
		)
		if err := rows.Scan(&cred.ID, &cred.UserID, &cred.CredentialID, &data,
			&cred.Nickname, &createdAt, &lastUsedAt); err != nil {
			return nil, err
		}
		cred.CredentialData = []byte(data)
		cred.CreatedAt = createdAt.Time
		cred.LastUsedAt = lastUsedAt.ptr()
		out = append(out, cred)
	}
	return out, rows.Err()
}

// Update persists the authenticator's updated state after a successful
// login — principally its signature counter, which is what makes
// cloned-authenticator detection possible. Matched on credential_id,
// not id, because that is what the login ceremony has in hand.
func (s *WebAuthnStore) Update(ctx context.Context, cred store.WebAuthnCredential) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE webauthn_credentials
		SET credential_data = ?, last_used_at = ?
		WHERE credential_id = ?
	`, string(cred.CredentialData), formatTime(time.Now()), cred.CredentialID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

// Delete removes one passkey. Scoped by user_id as well as
// credential_id so that knowing a credential ID is not enough to
// deregister someone else's passkey.
func (s *WebAuthnStore) Delete(ctx context.Context, userID string, credentialID []byte) error {
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM webauthn_credentials WHERE user_id = ? AND credential_id = ?
	`, userID, credentialID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

var _ store.WebAuthnCredentialStore = (*WebAuthnStore)(nil)
