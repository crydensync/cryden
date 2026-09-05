package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// TOTPStore is the SQLite implementation of store.TOTPStore.
type TOTPStore struct {
	db *sql.DB
}

// NewTOTPStore returns a TOTPStore backed by an already-open database.
// The caller owns db's lifecycle.
func NewTOTPStore(db *sql.DB) *TOTPStore {
	return &TOTPStore{db: db}
}

// Upsert stores a new secret for the user, replacing any existing one.
//
// This is one of the few Postgres-isms that needs no translation:
// SQLite has supported ON CONFLICT ... DO UPDATE since 3.24 (2018),
// comfortably below this package's floor.
//
// confirmed_at resets to NULL on conflict, which is the security-
// relevant half: re-enrolling produces a *new* secret, and the
// confirmation that proved possession of the old one says nothing about
// this one. Carrying it over would let an unverified secret gate logins.
func (s *TOTPStore) Upsert(ctx context.Context, secret store.TOTPSecret) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO totp_secrets (user_id, encrypted_secret, confirmed_at, created_at)
		VALUES (?, ?, NULL, ?)
		ON CONFLICT (user_id) DO UPDATE
		SET encrypted_secret = excluded.encrypted_secret, confirmed_at = NULL
	`, secret.UserID, secret.EncryptedSecret, formatTime(time.Now()))
	return err
}

func (s *TOTPStore) GetByUserID(ctx context.Context, userID string) (store.TOTPSecret, error) {
	var (
		secret      store.TOTPSecret
		confirmedAt scanTime
		createdAt   scanTime
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT user_id, encrypted_secret, confirmed_at, created_at
		FROM totp_secrets WHERE user_id = ?
	`, userID).Scan(&secret.UserID, &secret.EncryptedSecret, &confirmedAt, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return store.TOTPSecret{}, store.ErrNotFound
	}
	if err != nil {
		return store.TOTPSecret{}, err
	}
	secret.ConfirmedAt = confirmedAt.ptr()
	secret.CreatedAt = createdAt.Time
	return secret, nil
}

// Confirm marks the stored secret confirmed, after the user has proved
// possession with one valid code.
func (s *TOTPStore) Confirm(ctx context.Context, userID string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE totp_secrets SET confirmed_at = ? WHERE user_id = ?
	`, formatTime(time.Now()), userID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (s *TOTPStore) Delete(ctx context.Context, userID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM totp_secrets WHERE user_id = ?`, userID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

var _ store.TOTPStore = (*TOTPStore)(nil)
