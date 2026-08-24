package postgres

import (
	"context"
	"database/sql"
	"errors"

	_ "github.com/lib/pq"

	"github.com/crydensync/cryden/v2/store"
)

// OAuthStore is the v1 production store.OAuthStore implementation.
type OAuthStore struct {
	db *sql.DB
}

// NewOAuthStore wraps an existing *sql.DB. The caller owns the
// connection's lifecycle (opening, closing, pool sizing) — this
// package never opens or closes the DB itself.
func NewOAuthStore(db *sql.DB) *OAuthStore {
	return &OAuthStore{db: db}
}

func (s *OAuthStore) Link(ctx context.Context, identity store.OAuthIdentity) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oauth_identities (id, user_id, provider, external_id, email)
		VALUES ($1, $2, $3, $4, $5)
	`, identity.ID, identity.UserID, identity.Provider, identity.ExternalID, identity.Email)
	return err
}

func (s *OAuthStore) GetByProviderID(ctx context.Context, provider, externalID string) (store.OAuthIdentity, error) {
	var id store.OAuthIdentity
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, provider, external_id, email, created_at
		FROM oauth_identities WHERE provider = $1 AND external_id = $2
	`, provider, externalID).Scan(&id.ID, &id.UserID, &id.Provider, &id.ExternalID, &id.Email, &id.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return store.OAuthIdentity{}, store.ErrNotFound
	}
	return id, err
}

func (s *OAuthStore) ListByUser(ctx context.Context, userID string) ([]store.OAuthIdentity, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, provider, external_id, email, created_at
		FROM oauth_identities
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []store.OAuthIdentity{}
	for rows.Next() {
		var id store.OAuthIdentity
		if err := rows.Scan(&id.ID, &id.UserID, &id.Provider, &id.ExternalID, &id.Email, &id.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *OAuthStore) Unlink(ctx context.Context, identityID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM oauth_identities WHERE id = $1`, identityID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

var _ store.OAuthStore = (*OAuthStore)(nil)
