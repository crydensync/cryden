package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// AnomalyStore is the SQLite implementation of store.AnomalyStore.
type AnomalyStore struct {
	db *sql.DB
}

// NewAnomalyStore returns an AnomalyStore backed by an already-open
// database. The caller owns db's lifecycle.
func NewAnomalyStore(db *sql.DB) *AnomalyStore {
	return &AnomalyStore{db: db}
}

// RecordAttempt appends one login observation, assigning the ID and
// CreatedAt itself — the interface says so explicitly, and Postgres
// does it with gen_random_uuid() and DEFAULT now().
//
// An empty UserID becomes NULL, not "": a failure against an
// unrecognised email is real evidence about the IP and must be
// recorded, but it belongs to no account, and CountTargetsForIP counts
// exactly those NULL rows separately.
func (s *AnomalyStore) RecordAttempt(ctx context.Context, attempt store.LoginAttempt) error {
	id, err := newID()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO login_attempts (id, user_id, ip, user_agent, outcome, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, id, nullString(attempt.UserID), attempt.IP, attempt.UserAgent,
		string(attempt.Outcome), formatTime(time.Now()))
	return err
}

// ListRecentSuccesses returns the user's most recent successful
// attempts, newest first — the baseline new-IP and new-device detection
// compares against. Successes only, by design.
func (s *AnomalyStore) ListRecentSuccesses(ctx context.Context, userID string, limit int) ([]store.LoginAttempt, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, ip, user_agent, outcome, created_at
		FROM login_attempts
		WHERE user_id = ? AND outcome = 'success'
		ORDER BY created_at DESC
		LIMIT ?
	`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.LoginAttempt
	for rows.Next() {
		var (
			a         store.LoginAttempt
			uid       sql.NullString
			outcome   string
			createdAt scanTime
		)
		if err := rows.Scan(&a.ID, &uid, &a.IP, &a.UserAgent, &outcome, &createdAt); err != nil {
			return nil, err
		}
		a.UserID = uid.String
		a.Outcome = store.LoginAttemptOutcome(outcome)
		a.CreatedAt = createdAt.Time
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountFailuresForUser counts this user's failures at or after since.
//
// The comparison is a string comparison — created_at is fixed-width
// TEXT, which is what makes >= on it mean what it looks like it means.
// See this package's doc comment; the width is not cosmetic.
func (s *AnomalyStore) CountFailuresForUser(ctx context.Context, userID string, since time.Time) (int, error) {
	if userID == "" {
		return 0, nil
	}
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM login_attempts
		WHERE user_id = ? AND outcome = 'failure' AND created_at >= ?
	`, userID, formatTime(since)).Scan(&count)
	return count, err
}

// CountFailuresForIP counts failures from this IP at or after since,
// across every account it targeted, unknown-email attempts included.
func (s *AnomalyStore) CountFailuresForIP(ctx context.Context, ip string, since time.Time) (int, error) {
	if ip == "" {
		return 0, nil
	}
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM login_attempts
		WHERE ip = ? AND outcome = 'failure' AND created_at >= ?
	`, ip, formatTime(since)).Scan(&count)
	return count, err
}

// CountTargetsForIP reports how broadly the IP's failures were spread.
//
// Postgres writes the second number as COUNT(*) FILTER (WHERE user_id
// IS NULL). SQLite gained FILTER in 3.30, but this uses the older
// COUNT(CASE WHEN ...) form so the query also runs on the 3.24-era
// builds still shipping in long-term distributions.
//
// COUNT, not SUM: COUNT of zero matching rows is 0, whereas SUM over no
// rows is NULL and would need a COALESCE to scan into an int at all.
func (s *AnomalyStore) CountTargetsForIP(ctx context.Context, ip string, since time.Time) (store.IPTargetCounts, error) {
	if ip == "" {
		return store.IPTargetCounts{}, nil
	}
	var counts store.IPTargetCounts
	err := s.db.QueryRowContext(ctx, `
		SELECT
			COUNT(DISTINCT user_id),
			COUNT(CASE WHEN user_id IS NULL THEN 1 END)
		FROM login_attempts
		WHERE ip = ? AND outcome = 'failure' AND created_at >= ?
	`, ip, formatTime(since)).Scan(&counts.DistinctAccounts, &counts.UnknownTargetFailures)
	if err != nil {
		return store.IPTargetCounts{}, err
	}
	return counts, nil
}

var _ store.AnomalyStore = (*AnomalyStore)(nil)
