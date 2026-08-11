package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/crydensync/cryden/v2/store"
)

// VerificationStore is the v2 production store.VerificationStore
// implementation.
type VerificationStore struct {
	db *sql.DB
}

func NewVerificationStore(db *sql.DB) *VerificationStore {
	return &VerificationStore{db: db}
}

func (s *VerificationStore) Create(ctx context.Context, vt store.VerificationToken) error {
	var newEmail sql.NullString
	if vt.NewEmail != "" {
		newEmail = sql.NullString{String: vt.NewEmail, Valid: true}
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO verification_tokens (id, user_id, purpose, token_hash, new_email, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, vt.ID, vt.UserID, string(vt.Purpose), vt.TokenHash, newEmail, vt.ExpiresAt)
	return err
}

func (s *VerificationStore) GetByTokenHash(ctx context.Context, tokenHash string) (store.VerificationToken, error) {
	var vt store.VerificationToken
	var purpose string
	var newEmail sql.NullString
	var usedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, purpose, token_hash, new_email, expires_at, used_at, created_at
		FROM verification_tokens WHERE token_hash = $1
	`, tokenHash).Scan(&vt.ID, &vt.UserID, &purpose, &vt.TokenHash, &newEmail, &vt.ExpiresAt, &usedAt, &vt.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return store.VerificationToken{}, store.ErrNotFound
	}
	if err != nil {
		return store.VerificationToken{}, err
	}

	vt.Purpose = store.VerificationPurpose(purpose)
	if newEmail.Valid {
		vt.NewEmail = newEmail.String
	}
	if usedAt.Valid {
		vt.UsedAt = &usedAt.Time
	}
	return vt, nil
}

func (s *VerificationStore) MarkUsed(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE verification_tokens SET used_at = now() WHERE id = $1 AND used_at IS NULL
	`, id)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

var _ store.VerificationStore = (*VerificationStore)(nil)
