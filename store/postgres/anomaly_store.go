package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// AnomalyStore is the v2 production store.AnomalyStore implementation.
type AnomalyStore struct {
	db *sql.DB
}

func NewAnomalyStore(db *sql.DB) *AnomalyStore {
	return &AnomalyStore{db: db}
}

func (s *AnomalyStore) RecordAttempt(ctx context.Context, attempt store.LoginAttempt) error {
	// user_id is nullable in the schema — a failure against an email
	// that matches no account has no user to attribute to, and an empty
	// string is not a valid UUID. Same reasoning (and same fix) as
	// AuditStore.Record.
	var userID sql.NullString
	if attempt.UserID != "" {
		userID = sql.NullString{String: attempt.UserID, Valid: true}
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO login_attempts (id, user_id, ip, user_agent, outcome)
		VALUES (gen_random_uuid(), $1, $2, $3, $4)
	`, userID, attempt.IP, attempt.UserAgent, string(attempt.Outcome))
	return err
}

func (s *AnomalyStore) ListRecentSuccesses(ctx context.Context, userID string, limit int) ([]store.LoginAttempt, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, ip, user_agent, outcome, created_at
		FROM login_attempts
		WHERE user_id = $1 AND outcome = 'success'
		ORDER BY created_at DESC
		LIMIT $2
	`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []store.LoginAttempt{}
	for rows.Next() {
		var (
			a       store.LoginAttempt
			uid     sql.NullString
			outcome string
		)
		if err := rows.Scan(&a.ID, &uid, &a.IP, &a.UserAgent, &outcome, &a.CreatedAt); err != nil {
			return nil, err
		}
		if uid.Valid {
			a.UserID = uid.String
		}
		a.Outcome = store.LoginAttemptOutcome(outcome)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *AnomalyStore) CountFailuresForUser(ctx context.Context, userID string, since time.Time) (int, error) {
	// Guarded rather than passed straight through: user_id IS NULL for
	// unknown-email failures, and letting "" reach the query as a
	// parameter would either error on the UUID cast or, worse in a
	// backend that tolerates it, report every unattributed failure in
	// the system as this one user's history.
	if userID == "" {
		return 0, nil
	}
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM login_attempts
		WHERE user_id = $1 AND outcome = 'failure' AND created_at >= $2
	`, userID, since).Scan(&count)
	return count, err
}

func (s *AnomalyStore) CountFailuresForIP(ctx context.Context, ip string, since time.Time) (int, error) {
	if ip == "" {
		return 0, nil
	}
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM login_attempts
		WHERE ip = $1 AND outcome = 'failure' AND created_at >= $2
	`, ip, since).Scan(&count)
	return count, err
}

var _ store.AnomalyStore = (*AnomalyStore)(nil)
