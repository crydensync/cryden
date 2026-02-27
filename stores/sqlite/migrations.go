package sqlite

import (
	"database/sql"
	"fmt"
)

// Migrate creates the necessary tables if they don't exist
func Migrate(db *sql.DB) error {
	// Create users table
	usersTable := `
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    `

	_, err := db.Exec(usersTable)
	if err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	// Create sessions table
	sessionsTable := `
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            refresh_token TEXT UNIQUE NOT NULL,
            created_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token ON sessions(refresh_token);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
    `

	_, err = db.Exec(sessionsTable)
	if err != nil {
		return fmt.Errorf("failed to create sessions table: %w", err)
	}

	return nil
}
