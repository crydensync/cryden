package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// AuditStore is the SQLite implementation of store.AuditStore.
type AuditStore struct {
	db *sql.DB
}

// NewAuditStore returns an AuditStore backed by an already-open
// database. The caller owns db's lifecycle.
func NewAuditStore(db *sql.DB) *AuditStore {
	return &AuditStore{db: db}
}

// Record writes one audit event, assigning its ID and CreatedAt.
// Postgres does that with gen_random_uuid() and DEFAULT now(); SQLite
// has neither, so both come from Go — the same UUIDv7 generator the
// rest of the engine uses, which keeps IDs time-ordered.
func (s *AuditStore) Record(ctx context.Context, event store.AuditEvent) error {
	id, err := newID()
	if err != nil {
		return err
	}

	// Left as a nil any, not "", when there is no metadata: an empty
	// TEXT column would then have to be told apart from absent JSON on
	// the way back out.
	var metadata any
	if event.Metadata != nil {
		b, err := json.Marshal(event.Metadata)
		if err != nil {
			return err
		}
		metadata = string(b)
	}

	// nullString on the user ID: a login_failed event for an
	// unrecognised email has no user to attribute to, and "" is not a
	// user ID. NULL is the honest value, and the one this column's
	// ON DELETE SET NULL already uses.
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO audit_events (id, type, user_id, ip, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, id, string(event.Type), nullString(event.UserID), event.IP, metadata, formatTime(time.Now()))
	return err
}

// ListByUser returns the user's most recent events, newest first.
func (s *AuditStore) ListByUser(ctx context.Context, userID string, limit int) ([]store.AuditEvent, error) {
	return s.query(ctx, `WHERE user_id = ?`, userID, limit)
}

// SearchByType returns the most recent events of one type across all
// users, including those with no user attached.
func (s *AuditStore) SearchByType(ctx context.Context, eventType store.AuditEventType, limit int) ([]store.AuditEvent, error) {
	return s.query(ctx, `WHERE type = ?`, string(eventType), limit)
}

func (s *AuditStore) query(ctx context.Context, where string, arg any, limit int) ([]store.AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, user_id, ip, metadata, created_at
		FROM audit_events `+where+`
		ORDER BY created_at DESC
		LIMIT ?
	`, arg, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.AuditEvent
	for rows.Next() {
		var (
			e         store.AuditEvent
			eventType string
			uid       sql.NullString
			ip        sql.NullString
			metadata  sql.NullString
			createdAt scanTime
		)
		if err := rows.Scan(&e.ID, &eventType, &uid, &ip, &metadata, &createdAt); err != nil {
			return nil, err
		}
		e.Type = store.AuditEventType(eventType)
		e.UserID = uid.String
		e.IP = ip.String
		e.CreatedAt = createdAt.Time
		if metadata.Valid && metadata.String != "" {
			if err := json.Unmarshal([]byte(metadata.String), &e.Metadata); err != nil {
				return nil, err
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountByType counts the events recorded at or after since, grouped by
// type, in one query — no audit row leaves the database to be counted.
//
// The comparison is a string comparison, which is only correct because
// created_at is the package's fixed-width UTC layout: every timestamp
// is exactly the same length with the same offset, so lexicographic
// order is chronological order. formatTime is what guarantees that, and
// is why since goes through it rather than being passed as a time.Time
// for a driver to render however it likes.
//
// Unlike Postgres this one is indexed for free on the type side
// (idx_audit_events_type), though a GROUP BY over a date range still
// scans; a SQLite audit table is small enough that this is a
// non-question.
func (s *AuditStore) CountByType(ctx context.Context, since time.Time) (map[store.AuditEventType]int, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT type, COUNT(*)
		FROM audit_events
		WHERE created_at >= ?
		GROUP BY type
	`, formatTime(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[store.AuditEventType]int)
	for rows.Next() {
		var (
			eventType string
			n         int
		)
		if err := rows.Scan(&eventType, &n); err != nil {
			return nil, err
		}
		counts[store.AuditEventType(eventType)] = n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return counts, nil
}

var _ store.AuditStore = (*AuditStore)(nil)
