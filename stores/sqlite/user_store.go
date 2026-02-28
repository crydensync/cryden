/*package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/raymondproguy/credensync/core"
)

// UserStore implemtes core.UserStore using SQLite
type UserStore struct {
	db *sql.DB
}

// NewUserStore creates a new SQLite user store
func NewUserStore(dbPath string) (*UserStore, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	return &UserStore{db: db}, nil
}

// Create stores a new user
func (s *UserStore) Create(ctx context.Context, email, passwordHash string) (*core.User, error) {
	query := `
  INSERT INTO users (id, email, password_hash, created_at, updated_at)
  VALUES (?, ?, ?, ?, ?)
  RETURNING id, email, password_hash, created_at, upatated_at

	`

	now := time.Now()
	id := generateID()

	var user core.User
	err := s.db.QueryRowContext(ctx, query, id, email, passwordHash, now, now).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if isUniqueConstraintError(err) {
			return nil, core.ErrUserExists
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	return &user, nil
}

// GetByEmail retrieves a user by email
func (s *UserStore) GetByEmail(ctx context.Context, email string) (*core.User, error) {
	query := `
 SELECT id, email, password_hash, created_at, updated_at
 FROM users
 WHERE email = ?
`

	var user core.User
	err := s.db.QueryRowContext(ctx, query, email).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, core.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	return &user, nil
}

// GetByID retrieves a user by ID
func (s *UserStore) GetByID(ctx context.Context, id string) (*core.User, error) {
	query := `
 SELECT id, email, password_hash, created_at, updated_at
 FROM users
 WHERE id = ?
`

	var user core.User
	err := s.db.QueryRowContext(ctx, query, id).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, core.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}
	return &user, nil
}

// UpdateEmail changes a user's email
func (s *UserStore) UpdateEmail(ctx context.Context, id, newEmail string) error {
	query := `
  UPDATE users 
  SET email = ?, updated_at = ?
  WHERE id = ?
`
	result, err := s.db.ExecContext(ctx, query, newEmail, time.Now(), id)
	if err != nil {
		if isUniqueConstraintError(err) {
			return core.ErrUserExists
		}
		return fmt.Errorf("failed to update email: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return core.ErrUserNotFound
	}
	return nil
}

// UpdateEmail changes a user's password
func (s *UserStore) UpdatePassword(ctx context.Context, id, newPasswordHash string) error {
	query := `
  UPDATE users
  SET password_hash = ?, updated_at = ?
  WHERE id = ?
`
	result, err := s.db.ExecContext(ctx, query, newPasswordHash, time.Now(), id)
	if err != nil {
		if isUniqueConstraintError(err) {
			return core.ErrUserExists
		}
		return fmt.Errorf("failed to update password: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return core.ErrUserNotFound
	}
	return nil
}

// Delete removes a user
func (s *UserStore) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = ?`
	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return core.ErrUserNotFound
	}
	return nil
}

// Close closes the database connection
func (s *UserStore) Close() error {
	return s.db.Close()
}

// generateID creates a unique ID
func generateID() string {
	return fmt.Sprintf("usr_%d", time.Now().UnixNano())
}

// NewUserStoreWithDB creates a store with existing database connection
func NewUserStoreWithDB(db *sql.DB) (*UserStore, error) {
    return &UserStore{db: db}, nil
}

// isUniqueConstraintError checks if error is SQLite unique constraint violation
func isUniqueConstraintError(err error) bool {
	return err != nil && err.Error() == "UNIQUE constraint failed: users.email"
} 
*/

// stores/sqlite/user_store.go
package sqlite

import (
    "context"
    "database/sql"
    "fmt"
    "time"
    
    "github.com/raymondproguy/credensync/core"
    _ "github.com/mattn/go-sqlite3"
)

// UserStore implements core.UserStore using SQLite
type UserStore struct {
    db *sql.DB
}

// NewUserStore creates a new SQLite user store
func NewUserStore(dbPath string) (*UserStore, error) {
    db, err := sql.Open("sqlite3", dbPath)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %w", err)
    }
    
    // Test connection
    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }
    
    return &UserStore{db: db}, nil
}

// Create stores a new user
func (s *UserStore) Create(ctx context.Context, email, passwordHash string) (*core.User, error) {
    query := `
        INSERT INTO users (id, email, password_hash, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        RETURNING id, email, password_hash, created_at, updated_at
    `
    
    now := time.Now()
    id := generateID()
    
    var user core.User
    err := s.db.QueryRowContext(ctx, query,
        id, email, passwordHash, now, now,
    ).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
    
    if err != nil {
        // Check for unique constraint violation
        if isUniqueConstraintError(err) {
            return nil, core.ErrUserExists
        }
        return nil, fmt.Errorf("failed to create user: %w", err)
    }
    
    return &user, nil
}

// GetByEmail retrieves a user by email
func (s *UserStore) GetByEmail(ctx context.Context, email string) (*core.User, error) {
    query := `
        SELECT id, email, password_hash, created_at, updated_at
        FROM users
        WHERE email = ?
    `
    
    var user core.User
    err := s.db.QueryRowContext(ctx, query, email).Scan(
        &user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt,
    )
    
    if err == sql.ErrNoRows {
        return nil, core.ErrUserNotFound
    }
    if err != nil {
        return nil, fmt.Errorf("failed to get user by email: %w", err)
    }
    
    return &user, nil
}

// GetByID retrieves a user by ID
func (s *UserStore) GetByID(ctx context.Context, id string) (*core.User, error) {
    query := `
        SELECT id, email, password_hash, created_at, updated_at
        FROM users
        WHERE id = ?
    `
    
    var user core.User
    err := s.db.QueryRowContext(ctx, query, id).Scan(
        &user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt,
    )
    
    if err == sql.ErrNoRows {
        return nil, core.ErrUserNotFound
    }
    if err != nil {
        return nil, fmt.Errorf("failed to get user by ID: %w", err)
    }
    
    return &user, nil
}

// UpdateEmail changes a user's email
func (s *UserStore) UpdateEmail(ctx context.Context, id, newEmail string) error {
    query := `
        UPDATE users
        SET email = ?, updated_at = ?
        WHERE id = ?
    `
    
    result, err := s.db.ExecContext(ctx, query, newEmail, time.Now(), id)
    if err != nil {
        if isUniqueConstraintError(err) {
            return core.ErrUserExists
        }
        return fmt.Errorf("failed to update email: %w", err)
    }
    
    rows, err := result.RowsAffected()
    if err != nil {
        return fmt.Errorf("failed to get rows affected: %w", err)
    }
    if rows == 0 {
        return core.ErrUserNotFound
    }
    
    return nil
}

// UpdatePassword changes a user's password
func (s *UserStore) UpdatePassword(ctx context.Context, id, newPasswordHash string) error {
    query := `
        UPDATE users
        SET password_hash = ?, updated_at = ?
        WHERE id = ?
    `
    
    result, err := s.db.ExecContext(ctx, query, newPasswordHash, time.Now(), id)
    if err != nil {
        return fmt.Errorf("failed to update password: %w", err)
    }
    
    rows, err := result.RowsAffected()
    if err != nil {
        return fmt.Errorf("failed to get rows affected: %w", err)
    }
    if rows == 0 {
        return core.ErrUserNotFound
    }
    
    return nil
}

// Delete removes a user
func (s *UserStore) Delete(ctx context.Context, id string) error {
    query := `DELETE FROM users WHERE id = ?`
    
    result, err := s.db.ExecContext(ctx, query, id)
    if err != nil {
        return fmt.Errorf("failed to delete user: %w", err)
    }
    
    rows, err := result.RowsAffected()
    if err != nil {
        return fmt.Errorf("failed to get rows affected: %w", err)
    }
    if rows == 0 {
        return core.ErrUserNotFound
    }
    
    return nil
}

// Close closes the database connection
func (s *UserStore) Close() error {
    return s.db.Close()
}

// generateID creates a unique ID
func generateID() string {
    return fmt.Sprintf("usr_%d", time.Now().UnixNano())
}

// Add this function to user_store.go
// NewUserStoreWithDB creates a store with existing database connection
func NewUserStoreWithDB(db *sql.DB) (*UserStore, error) {
    return &UserStore{db: db}, nil
}

// isUniqueConstraintError checks if error is SQLite unique constraint violation
func isUniqueConstraintError(err error) bool {
    // SQLite unique constraint violation code is 1555 or 2067
    // This is a simple check - we can improve later
    return err != nil && err.Error() == "UNIQUE constraint failed: users.email"
}
