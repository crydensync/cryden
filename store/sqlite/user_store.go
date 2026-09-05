package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// UserStore is the SQLite implementation of store.UserStore.
type UserStore struct {
	db *sql.DB
}

// NewUserStore returns a UserStore backed by an already-open database.
// The caller owns db's lifecycle — this store never opens or closes it.
func NewUserStore(db *sql.DB) *UserStore {
	return &UserStore{db: db}
}

// Create inserts a new user. CreatedAt and UpdatedAt are assigned here,
// not taken from u: the Postgres schema defaults both columns to now()
// and ignores whatever the caller put in the struct, so this backend
// does the same thing rather than quietly honouring a field its
// counterpart discards.
func (s *UserStore) Create(ctx context.Context, u store.User) error {
	now := formatTime(time.Now())
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, email, password_hash, failed_attempts, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, u.ID, u.Email, u.PasswordHash, u.FailedAttempts, now, now)
	return err
}

func (s *UserStore) GetByEmail(ctx context.Context, email string) (store.User, error) {
	return s.getOne(ctx, `WHERE email = ?`, email)
}

func (s *UserStore) GetByID(ctx context.Context, id string) (store.User, error) {
	return s.getOne(ctx, `WHERE id = ?`, id)
}

// getOne is the single place a users row becomes a store.User, so the
// two lookups can never drift in which columns they read or how they
// map a missing row.
func (s *UserStore) getOne(ctx context.Context, where string, arg any) (store.User, error) {
	var (
		u           store.User
		lockedUntil scanTime
		createdAt   scanTime
		updatedAt   scanTime
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, email, password_hash, failed_attempts, locked_until, created_at, updated_at
		FROM users `+where, arg).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.FailedAttempts, &lockedUntil, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return store.User{}, store.ErrNotFound
	}
	if err != nil {
		return store.User{}, err
	}
	u.LockedUntil = lockedUntil.ptr()
	u.CreatedAt = createdAt.Time
	u.UpdatedAt = updatedAt.Time
	return u, nil
}

func (s *UserStore) UpdateEmail(ctx context.Context, userID, newEmail string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE users SET email = ?, updated_at = ? WHERE id = ?
	`, newEmail, formatTime(time.Now()), userID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (s *UserStore) UpdatePasswordHash(ctx context.Context, userID, newHash string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?
	`, newHash, formatTime(time.Now()), userID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

// Delete removes the user and everything hanging off them, in one
// transaction, by hand.
//
// The schema declares ON DELETE CASCADE, but SQLite only honours those
// when foreign_keys is on — and it is OFF by default, per connection,
// settable only from the DSN (see this package's doc comment). A host
// that forgets that pragma would otherwise get a deleted account whose
// session rows survive: refresh tokens that keep rotating for a user
// who no longer exists. That is a security hole, not a tidiness
// problem, so the cascade is written out here and correctness never
// depends on how the caller spelled its DSN.
//
// Order matters: children first, user last, so no statement can leave a
// row pointing at a user that is already gone. audit_events and
// login_attempts are NULLed rather than deleted, matching Postgres's
// ON DELETE SET NULL — the security record of what happened outlives
// the account it happened to.
func (s *UserStore) Delete(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, stmt := range []string{
		`DELETE FROM sessions WHERE user_id = ?`,
		`DELETE FROM verification_tokens WHERE user_id = ?`,
		`DELETE FROM oauth_identities WHERE user_id = ?`,
		`DELETE FROM totp_secrets WHERE user_id = ?`,
		`DELETE FROM webauthn_credentials WHERE user_id = ?`,
		`DELETE FROM recovery_codes WHERE user_id = ?`,
		`UPDATE audit_events SET user_id = NULL WHERE user_id = ?`,
		`UPDATE login_attempts SET user_id = NULL WHERE user_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, stmt, id); err != nil {
			return err
		}
	}

	result, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if err := checkRowsAffected(result); err != nil {
		return err
	}
	return tx.Commit()
}

// IncrementFailedAttempts bumps the counter and returns its new value.
//
// Postgres does this in one statement with UPDATE ... RETURNING.
// SQLite only learned RETURNING in 3.35 (March 2021), and plenty of
// still-supported distributions ship older — Debian bullseye is on
// 3.34.1 — so this reads the value back in a second statement instead.
// Both statements share one transaction, which is what keeps the
// returned number the one this call produced rather than one a
// concurrent attempt slipped in between them.
func (s *UserStore) IncrementFailedAttempts(ctx context.Context, userID string) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `
		UPDATE users SET failed_attempts = failed_attempts + 1, updated_at = ? WHERE id = ?
	`, formatTime(time.Now()), userID)
	if err != nil {
		return 0, err
	}
	if err := checkRowsAffected(result); err != nil {
		return 0, err
	}

	var attempts int
	if err := tx.QueryRowContext(ctx, `SELECT failed_attempts FROM users WHERE id = ?`, userID).Scan(&attempts); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return attempts, nil
}

// ResetFailedAttempts zeroes the counter and clears any lock. Not an
// error if the user was never locked or had no failures.
func (s *UserStore) ResetFailedAttempts(ctx context.Context, userID string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?
	`, formatTime(time.Now()), userID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (s *UserStore) LockAccount(ctx context.Context, userID string, until time.Time) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE users SET locked_until = ?, updated_at = ? WHERE id = ?
	`, formatTime(until), formatTime(time.Now()), userID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

// ListAll returns users newest-first, for admin screens. created_at is
// fixed-width TEXT, so ORDER BY on it is chronological — see this
// package's doc comment for why that width is load-bearing.
func (s *UserStore) ListAll(ctx context.Context, limit, offset int) ([]store.User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, email, password_hash, failed_attempts, locked_until, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []store.User
	for rows.Next() {
		var (
			u           store.User
			lockedUntil scanTime
			createdAt   scanTime
			updatedAt   scanTime
		)
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.FailedAttempts, &lockedUntil, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		u.LockedUntil = lockedUntil.ptr()
		u.CreatedAt = createdAt.Time
		u.UpdatedAt = updatedAt.Time
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *UserStore) Count(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

var _ store.UserStore = (*UserStore)(nil)
