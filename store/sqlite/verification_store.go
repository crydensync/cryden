package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// VerificationStore is the SQLite implementation of
// store.VerificationStore.
type VerificationStore struct {
	db *sql.DB
}

// NewVerificationStore returns a VerificationStore backed by an
// already-open database. The caller owns db's lifecycle.
func NewVerificationStore(db *sql.DB) *VerificationStore {
	return &VerificationStore{db: db}
}

// Create records a verification token. ExpiresAt comes from the caller
// — unlike CreatedAt, it is a real parameter in Postgres too, because
// only the caller knows the lifetime this particular purpose wants.
func (s *VerificationStore) Create(ctx context.Context, vt store.VerificationToken) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO verification_tokens (id, user_id, purpose, token_hash, new_email, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, vt.ID, vt.UserID, string(vt.Purpose), vt.TokenHash,
		nullString(vt.NewEmail), formatTime(vt.ExpiresAt), formatTime(time.Now()))
	return err
}

// GetByTokenHash returns the token row, expired or already-used
// included. Deciding what to do about either is the caller's job: the
// distinction between "no such token" and "a token that has expired"
// is one the auth layer needs in order to report it.
func (s *VerificationStore) GetByTokenHash(ctx context.Context, tokenHash string) (store.VerificationToken, error) {
	var (
		vt        store.VerificationToken
		purpose   string
		newEmail  sql.NullString
		expiresAt scanTime
		usedAt    scanTime
		createdAt scanTime
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, purpose, token_hash, new_email, expires_at, used_at, created_at
		FROM verification_tokens WHERE token_hash = ?
	`, tokenHash).Scan(&vt.ID, &vt.UserID, &purpose, &vt.TokenHash,
		&newEmail, &expiresAt, &usedAt, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return store.VerificationToken{}, store.ErrNotFound
	}
	if err != nil {
		return store.VerificationToken{}, err
	}
	vt.Purpose = store.VerificationPurpose(purpose)
	vt.NewEmail = newEmail.String
	vt.ExpiresAt = expiresAt.Time
	vt.UsedAt = usedAt.ptr()
	vt.CreatedAt = createdAt.Time
	return vt, nil
}

// MarkUsed burns the token. The AND is what makes it single-use even
// under a race: two concurrent redemptions of the same token, and only
// the one whose UPDATE matched a row gets nil back — the other gets
// store.ErrNotFound.
func (s *VerificationStore) MarkUsed(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE verification_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL
	`, formatTime(time.Now()), id)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

var _ store.VerificationStore = (*VerificationStore)(nil)
