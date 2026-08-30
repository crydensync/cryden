package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/crydensync/cryden/v2/store"
)

// TOTPStore is the v2 production store.TOTPStore implementation.
type TOTPStore struct {
	db *sql.DB
}

func NewTOTPStore(db *sql.DB) *TOTPStore {
	return &TOTPStore{db: db}
}

func (s *TOTPStore) Upsert(ctx context.Context, secret store.TOTPSecret) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO totp_secrets (user_id, encrypted_secret, confirmed_at)
		VALUES ($1, $2, NULL)
		ON CONFLICT (user_id) DO UPDATE
		SET encrypted_secret = EXCLUDED.encrypted_secret, confirmed_at = NULL
	`, secret.UserID, secret.EncryptedSecret)
	return err
}

func (s *TOTPStore) GetByUserID(ctx context.Context, userID string) (store.TOTPSecret, error) {
	var secret store.TOTPSecret
	var confirmedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT user_id, encrypted_secret, confirmed_at, created_at
		FROM totp_secrets WHERE user_id = $1
	`, userID).Scan(&secret.UserID, &secret.EncryptedSecret, &confirmedAt, &secret.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return store.TOTPSecret{}, store.ErrNotFound
	}
	if err != nil {
		return store.TOTPSecret{}, err
	}
	if confirmedAt.Valid {
		secret.ConfirmedAt = &confirmedAt.Time
	}
	return secret, nil
}

func (s *TOTPStore) Confirm(ctx context.Context, userID string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE totp_secrets SET confirmed_at = now() WHERE user_id = $1
	`, userID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (s *TOTPStore) Delete(ctx context.Context, userID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM totp_secrets WHERE user_id = $1`, userID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

var _ store.TOTPStore = (*TOTPStore)(nil)
