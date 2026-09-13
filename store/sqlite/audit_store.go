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

var _ store.AuditStore = (*AuditStore)(nil)
