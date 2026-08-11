package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/crydensync/cryden/v2/store"
)

// SessionStore is the v2 production store.SessionStore implementation.
type SessionStore struct {
	db *sql.DB
}

func NewSessionStore(db *sql.DB) *SessionStore {
	return &SessionStore{db: db}
}

func (s *SessionStore) Create(ctx context.Context, sess store.Session) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, family_id, user_id, token_hash, ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, sess.ID, sess.FamilyID, sess.UserID, sess.TokenHash, sess.IP, sess.UserAgent)
	return err
}

func (s *SessionStore) GetByID(ctx context.Context, sessionID string) (store.Session, error) {
	return s.scanOne(ctx, `
		SELECT id, family_id, user_id, token_hash, ip, user_agent, created_at, revoked_at
		FROM sessions WHERE id = $1
	`, sessionID)
}

func (s *SessionStore) GetByTokenHash(ctx context.Context, tokenHash string) (store.Session, error) {
	return s.scanOne(ctx, `
		SELECT id, family_id, user_id, token_hash, ip, user_agent, created_at, revoked_at
		FROM sessions WHERE token_hash = $1
	`, tokenHash)
}

func (s *SessionStore) scanOne(ctx context.Context, query string, arg string) (store.Session, error) {
	var sess store.Session
	var revokedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, query, arg).Scan(
		&sess.ID, &sess.FamilyID, &sess.UserID, &sess.TokenHash,
		&sess.IP, &sess.UserAgent, &sess.CreatedAt, &revokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return store.Session{}, store.ErrNotFound
	}
	if err != nil {
		return store.Session{}, err
	}
	if revokedAt.Valid {
		sess.RevokedAt = &revokedAt.Time
	}
	return sess, nil
}

func (s *SessionStore) ListByUser(ctx context.Context, userID string) ([]store.Session, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, family_id, user_id, token_hash, ip, user_agent, created_at, revoked_at
		FROM sessions
		WHERE user_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.Session
	for rows.Next() {
		var sess store.Session
		var revokedAt sql.NullTime
		if err := rows.Scan(&sess.ID, &sess.FamilyID, &sess.UserID, &sess.TokenHash,
			&sess.IP, &sess.UserAgent, &sess.CreatedAt, &revokedAt); err != nil {
			return nil, err
		}
		if revokedAt.Valid {
			sess.RevokedAt = &revokedAt.Time
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *SessionStore) Revoke(ctx context.Context, sessionID string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL
	`, sessionID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (s *SessionStore) RevokeFamily(ctx context.Context, familyID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET revoked_at = now()
		WHERE family_id = $1 AND revoked_at IS NULL
	`, familyID)
	return err
}

func (s *SessionStore) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET revoked_at = now()
		WHERE user_id = $1 AND revoked_at IS NULL
	`, userID)
	return err
}

// RotateToken revokes oldSessionID and creates newSession inside a
// single DB transaction — the atomicity guarantee the interface
// promises. If the process crashes mid-transaction, Postgres rolls
// back automatically; there is no window where the old token is dead
// but the new one was never created.
func (s *SessionStore) RotateToken(ctx context.Context, oldSessionID string, newSession store.Session) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op if Commit succeeds

	result, err := tx.ExecContext(ctx, `
		UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL
	`, oldSessionID)
	if err != nil {
		return err
	}
	if err := checkRowsAffected(result); err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO sessions (id, family_id, user_id, token_hash, ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, newSession.ID, newSession.FamilyID, newSession.UserID, newSession.TokenHash,
		newSession.IP, newSession.UserAgent)
	if err != nil {
		return err
	}

	return tx.Commit()
}

var _ store.SessionStore = (*SessionStore)(nil)
