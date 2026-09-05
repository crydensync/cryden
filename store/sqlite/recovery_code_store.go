package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// RecoveryCodeStore is the SQLite implementation of
// store.RecoveryCodeStore.
type RecoveryCodeStore struct {
	db *sql.DB
}

// NewRecoveryCodeStore returns a RecoveryCodeStore backed by an
// already-open database. The caller owns db's lifecycle.
func NewRecoveryCodeStore(db *sql.DB) *RecoveryCodeStore {
	return &RecoveryCodeStore{db: db}
}

// ReplaceAll wipes the user's existing codes and inserts the new batch,
// in one transaction. The transaction is the point: a crash between the
// delete and the inserts would otherwise leave an account with 2FA
// enabled and no recovery codes at all, which is exactly the state
// recovery codes exist to prevent.
func (s *RecoveryCodeStore) ReplaceAll(ctx context.Context, userID string, codes []store.RecoveryCode) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := formatTime(time.Now())
	for _, code := range codes {
		if _, err := stmt.ExecContext(ctx, userID, code.CodeHash, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *RecoveryCodeStore) CountUnused(ctx context.Context, userID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL
	`, userID).Scan(&count)
	return count, err
}

// Consume marks one matching unused code used, atomically. The
// used_at IS NULL in the WHERE clause is what makes a code single-use:
// two concurrent attempts with the same code, and only the one whose
// UPDATE matched a row succeeds. store.ErrNotFound covers all three
// failures the caller must not be able to tell apart — wrong code,
// already-used code, and no codes at all.
func (s *RecoveryCodeStore) Consume(ctx context.Context, userID, codeHash string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE recovery_codes SET used_at = ?
		WHERE user_id = ? AND code_hash = ? AND used_at IS NULL
	`, formatTime(time.Now()), userID, codeHash)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

// DeleteAll removes every code for the user. Not an error if there were
// none — this is hygiene, and "already clean" is the desired end state.
func (s *RecoveryCodeStore) DeleteAll(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID)
	return err
}

var _ store.RecoveryCodeStore = (*RecoveryCodeStore)(nil)
