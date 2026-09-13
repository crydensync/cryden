package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// SessionStore is the SQLite implementation of store.SessionStore.
type SessionStore struct {
	db *sql.DB
}

// NewSessionStore returns a SessionStore backed by an already-open
// database. The caller owns db's lifecycle.
func NewSessionStore(db *sql.DB) *SessionStore {
	return &SessionStore{db: db}
}

// Create records a new session. CreatedAt is assigned here rather than
// read from sess, matching the Postgres schema's DEFAULT now().
func (s *SessionStore) Create(ctx context.Context, sess store.Session) error {
	_, err := s.db.ExecContext(ctx, insertSessionSQL,
		sess.ID, sess.FamilyID, sess.UserID, sess.TokenHash,
		sess.IP, sess.UserAgent, formatTime(time.Now()))
	return err
}

// Shared by Create and RotateToken so a rotated session is stored
// exactly like a freshly created one.
const insertSessionSQL = `
	INSERT INTO sessions (id, family_id, user_id, token_hash, ip, user_agent, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?)
`

func (s *SessionStore) GetByID(ctx context.Context, sessionID string) (store.Session, error) {
	return s.getOne(ctx, `WHERE id = ?`, sessionID)
}

func (s *SessionStore) GetByTokenHash(ctx context.Context, tokenHash string) (store.Session, error) {
	return s.getOne(ctx, `WHERE token_hash = ?`, tokenHash)
}

// getOne deliberately returns revoked sessions too. Refresh-token
// rotation needs to be able to see a dead session in order to detect
// reuse of its token — a lookup that hid them would turn a replay
// attack into a plain "not found".
func (s *SessionStore) getOne(ctx context.Context, where string, arg any) (store.Session, error) {
	var (
		sess      store.Session
		createdAt scanTime
		revokedAt scanTime
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, family_id, user_id, token_hash, ip, user_agent, created_at, revoked_at
		FROM sessions `+where, arg).
		Scan(&sess.ID, &sess.FamilyID, &sess.UserID, &sess.TokenHash,
			&sess.IP, &sess.UserAgent, &createdAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return store.Session{}, store.ErrNotFound
	}
	if err != nil {
		return store.Session{}, err
	}
	sess.CreatedAt = createdAt.Time
	sess.RevokedAt = revokedAt.ptr()
	return sess, nil
}

// ListByUser returns the user's active sessions, newest first. Revoked
// ones are omitted — this is what "where am I logged in" screens read.
func (s *SessionStore) ListByUser(ctx context.Context, userID string) ([]store.Session, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, family_id, user_id, token_hash, ip, user_agent, created_at, revoked_at
		FROM sessions
		WHERE user_id = ? AND revoked_at IS NULL
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.Session
	for rows.Next() {
		var (
			sess      store.Session
			createdAt scanTime
			revokedAt scanTime
		)
		if err := rows.Scan(&sess.ID, &sess.FamilyID, &sess.UserID, &sess.TokenHash,
			&sess.IP, &sess.UserAgent, &createdAt, &revokedAt); err != nil {
			return nil, err
		}
		sess.CreatedAt = createdAt.Time
		sess.RevokedAt = revokedAt.ptr()
		out = append(out, sess)
	}
	return out, rows.Err()
}

// Revoke marks one session dead. Already-revoked sessions keep their
// original revoked_at: the AND below means a second Revoke matches no
// row and returns store.ErrNotFound, the same as Postgres.
func (s *SessionStore) Revoke(ctx context.Context, sessionID string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL
	`, formatTime(time.Now()), sessionID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

// RevokeFamily kills every session in one rotation family — the
// response to detecting a reused refresh token. Not an error if the
// family is already fully revoked: unlike Revoke, this is called from
// the middle of incident response, where "nothing left to do" is a
// success, not a missing row.
func (s *SessionStore) RevokeFamily(ctx context.Context, familyID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL
	`, formatTime(time.Now()), familyID)
	return err
}

// RevokeAllForUser is "log out everywhere". Same tolerance for zero
// rows as RevokeFamily.
func (s *SessionStore) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL
	`, formatTime(time.Now()), userID)
	return err
}

// RotateToken revokes the old session and creates the new one inside a
// single transaction, so a crash mid-rotation can never leave a family
// with its old token dead and no new one issued.
func (s *SessionStore) RotateToken(ctx context.Context, oldSessionID string, newSession store.Session) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now()
	result, err := tx.ExecContext(ctx, `
		UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL
	`, formatTime(now), oldSessionID)
	if err != nil {
		return err
	}
	if err := checkRowsAffected(result); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, insertSessionSQL,
		newSession.ID, newSession.FamilyID, newSession.UserID, newSession.TokenHash,
		newSession.IP, newSession.UserAgent, formatTime(now)); err != nil {
		return err
	}
	return tx.Commit()
}

// CountActive counts non-revoked sessions system-wide, not per user.
func (s *SessionStore) CountActive(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL
	`).Scan(&count)
	return count, err
}

var _ store.SessionStore = (*SessionStore)(nil)
