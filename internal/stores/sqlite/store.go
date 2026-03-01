package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/crydensync/cryden/internal/core"
)

type UserStore struct {
	db *sql.DB
}

func NewUserStore(dbPath string) (*UserStore, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	if err := autoMigrate(db); err != nil {
		return nil, fmt.Errorf("failed to migrate: %w", err)
	}

	return &UserStore{db: db}, nil
}

func autoMigrate(db *sql.DB) error {
	usersTable := `
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    `

	if _, err := db.Exec(usersTable); err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	sessionsTable := `
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            refresh_token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token ON sessions(refresh_token);
    `

	if _, err := db.Exec(sessionsTable); err != nil {
		return fmt.Errorf("failed to create sessions table: %w", err)
	}

	return nil
}

func (s *UserStore) Create(ctx context.Context, email, passwordHash string) (*core.User, error) {
	query := `
        INSERT INTO users (id, email, password_hash, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        RETURNING id, email, password_hash, created_at, updated_at
    `

	now := time.Now()
	id := fmt.Sprintf("usr_%d", time.Now().UnixNano())

	var user core.User
	err := s.db.QueryRowContext(ctx, query,
		id, email, passwordHash, now, now,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err.Error() == "UNIQUE constraint failed: users.email" {
			return nil, core.ErrUserExists
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &user, nil
}

func (s *UserStore) GetByEmail(ctx context.Context, email string) (*core.User, error) {
	query := `SELECT id, email, password_hash, created_at, updated_at FROM users WHERE email = ?`

	var user core.User
	err := s.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, core.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

func (s *UserStore) GetByID(ctx context.Context, id string) (*core.User, error) {
	query := `SELECT id, email, password_hash, created_at, updated_at FROM users WHERE id = ?`

	var user core.User
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, core.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

func (s *UserStore) UpdateEmail(ctx context.Context, id, newEmail string) error {
	query := `UPDATE users SET email = ?, updated_at = ? WHERE id = ?`

	result, err := s.db.ExecContext(ctx, query, newEmail, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update email: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return core.ErrUserNotFound
	}

	return nil
}

func (s *UserStore) UpdatePassword(ctx context.Context, id, newPasswordHash string) error {
	query := `UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`

	result, err := s.db.ExecContext(ctx, query, newPasswordHash, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return core.ErrUserNotFound
	}

	return nil
}

func (s *UserStore) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = ?`

	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return core.ErrUserNotFound
	}

	return nil
}

func (s *UserStore) Close() error {
	return s.db.Close()
}
