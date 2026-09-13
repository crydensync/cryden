package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// OAuthStore is the SQLite implementation of store.OAuthStore.
type OAuthStore struct {
	db *sql.DB
}

// NewOAuthStore returns an OAuthStore backed by an already-open
// database. The caller owns db's lifecycle.
func NewOAuthStore(db *sql.DB) *OAuthStore {
	return &OAuthStore{db: db}
}

// Link records that an external account belongs to a local user. The
// UNIQUE (provider, external_id) constraint is what stops the same
// external account being linked to two local users, and a violation
// surfaces as the driver's own error rather than store.ErrNotFound —
// it is a conflict, not a lookup failure.
func (s *OAuthStore) Link(ctx context.Context, identity store.OAuthIdentity) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oauth_identities (id, user_id, provider, external_id, email, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, identity.ID, identity.UserID, identity.Provider, identity.ExternalID,
		identity.Email, formatTime(time.Now()))
	return err
}

func (s *OAuthStore) GetByProviderID(ctx context.Context, provider, externalID string) (store.OAuthIdentity, error) {
	var (
		oi        store.OAuthIdentity
		createdAt scanTime
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, provider, external_id, email, created_at
		FROM oauth_identities WHERE provider = ? AND external_id = ?
	`, provider, externalID).Scan(&oi.ID, &oi.UserID, &oi.Provider, &oi.ExternalID, &oi.Email, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return store.OAuthIdentity{}, store.ErrNotFound
	}
	if err != nil {
		return store.OAuthIdentity{}, err
	}
	oi.CreatedAt = createdAt.Time
	return oi, nil
}

// ListByUser returns every external account linked to one user,
// newest first, matching Postgres.
func (s *OAuthStore) ListByUser(ctx context.Context, userID string) ([]store.OAuthIdentity, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, provider, external_id, email, created_at
		FROM oauth_identities WHERE user_id = ?
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.OAuthIdentity
	for rows.Next() {
		var (
			oi        store.OAuthIdentity
			createdAt scanTime
		)
		if err := rows.Scan(&oi.ID, &oi.UserID, &oi.Provider, &oi.ExternalID, &oi.Email, &createdAt); err != nil {
			return nil, err
		}
		oi.CreatedAt = createdAt.Time
		out = append(out, oi)
	}
	return out, rows.Err()
}

func (s *OAuthStore) Unlink(ctx context.Context, identityID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM oauth_identities WHERE id = ?`, identityID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

var _ store.OAuthStore = (*OAuthStore)(nil)
