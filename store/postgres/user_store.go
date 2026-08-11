package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	_ "github.com/lib/pq"

	"github.com/crydensync/cryden/v2/store"
)

// UserStore is the v2 production store.UserStore implementation.
type UserStore struct {
	db *sql.DB
}

// NewUserStore wraps an existing *sql.DB. The caller owns the
// connection's lifecycle (opening, closing, pool sizing) — this
// package never opens or closes the DB itself.
func NewUserStore(db *sql.DB) *UserStore {
	return &UserStore{db: db}
}

func (s *UserStore) Create(ctx context.Context, user store.User) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, email, password_hash)
		VALUES ($1, $2, $3)
	`, user.ID, user.Email, user.PasswordHash)
	return err
}

func (s *UserStore) GetByEmail(ctx context.Context, email string) (store.User, error) {
	var u store.User
	var lockedUntil sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT id, email, password_hash, failed_attempts, locked_until, created_at, updated_at
		FROM users WHERE email = $1
	`, email).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.FailedAttempts, &lockedUntil, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return store.User{}, store.ErrNotFound
	}
	if lockedUntil.Valid {
		u.LockedUntil = &lockedUntil.Time
	}
	return u, err
}

func (s *UserStore) GetByID(ctx context.Context, id string) (store.User, error) {
	var u store.User
	var lockedUntil sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT id, email, password_hash, failed_attempts, locked_until, created_at, updated_at
		FROM users WHERE id = $1
	`, id).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.FailedAttempts, &lockedUntil, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return store.User{}, store.ErrNotFound
	}
	if lockedUntil.Valid {
		u.LockedUntil = &lockedUntil.Time
	}
	return u, err
}

func (s *UserStore) UpdateEmail(ctx context.Context, id string, newEmail string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE users SET email = $1, updated_at = now() WHERE id = $2
	`, newEmail, id)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (s *UserStore) UpdatePasswordHash(ctx context.Context, id string, newHash string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2
	`, newHash, id)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (s *UserStore) Delete(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

// checkRowsAffected converts a zero-rows-affected UPDATE/DELETE into
// store.ErrNotFound, so callers get consistent not-found semantics
// regardless of which store method they called.
func checkRowsAffected(result sql.Result) error {
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *UserStore) IncrementFailedAttempts(ctx context.Context, id string) (int, error) {
	var attempts int
	err := s.db.QueryRowContext(ctx, `
		UPDATE users SET failed_attempts = failed_attempts + 1
		WHERE id = $1
		RETURNING failed_attempts
	`, id).Scan(&attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, store.ErrNotFound
	}
	return attempts, err
}

func (s *UserStore) ResetFailedAttempts(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1
	`, id)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (s *UserStore) LockAccount(ctx context.Context, id string, until time.Time) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE users SET locked_until = $1 WHERE id = $2
	`, until, id)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

var _ store.UserStore = (*UserStore)(nil)
