package postgres

import (
	"context"
	"database/sql"

	"github.com/crydensync/cryden/v2/store"
)

// RecoveryCodeStore is the v2 production store.RecoveryCodeStore
// implementation.
type RecoveryCodeStore struct {
	db *sql.DB
}

func NewRecoveryCodeStore(db *sql.DB) *RecoveryCodeStore {
	return &RecoveryCodeStore{db: db}
}

func (s *RecoveryCodeStore) ReplaceAll(ctx context.Context, userID string, codes []store.RecoveryCode) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	for _, c := range codes {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)
		`, userID, c.CodeHash); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *RecoveryCodeStore) CountUnused(ctx context.Context, userID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL
	`, userID).Scan(&count)
	return count, err
}

func (s *RecoveryCodeStore) Consume(ctx context.Context, userID string, codeHash string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE recovery_codes SET used_at = now()
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
	`, userID, codeHash)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (s *RecoveryCodeStore) DeleteAll(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID)
	return err
}

var _ store.RecoveryCodeStore = (*RecoveryCodeStore)(nil)
