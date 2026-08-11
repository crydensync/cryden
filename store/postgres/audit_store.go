package postgres

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/crydensync/cryden/v2/store"
)

// AuditStore is the v2 production store.AuditStore implementation.
type AuditStore struct {
	db *sql.DB
}

func NewAuditStore(db *sql.DB) *AuditStore {
	return &AuditStore{db: db}
}

func (s *AuditStore) Record(ctx context.Context, event store.AuditEvent) error {
	// user_id is nullable in the schema — a login_failed event for a
	// nonexistent email has no valid user to attribute to, and an
	// empty string is not a valid UUID. sql.NullString maps a Go ""
	// (or explicitly unset) UserID to a real SQL NULL instead of
	// erroring on insert.
	var userID sql.NullString
	if event.UserID != "" {
		userID = sql.NullString{String: event.UserID, Valid: true}
	}

	var metadata []byte
	if event.Metadata != nil {
		b, err := json.Marshal(event.Metadata)
		if err != nil {
			return err
		}
		metadata = b
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_events (id, type, user_id, ip, metadata)
		VALUES (gen_random_uuid(), $1, $2, $3, $4)
	`, string(event.Type), userID, event.IP, metadata)
	return err
}

func (s *AuditStore) ListByUser(ctx context.Context, userID string, limit int) ([]store.AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, user_id, ip, metadata, created_at
		FROM audit_events
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, userID, limit)
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
			metadata  []byte
		)
		if err := rows.Scan(&e.ID, &eventType, &uid, &e.IP, &metadata, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Type = store.AuditEventType(eventType)
		if uid.Valid {
			e.UserID = uid.String
		}
		if metadata != nil {
			if err := json.Unmarshal(metadata, &e.Metadata); err != nil {
				return nil, err
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

var _ store.AuditStore = (*AuditStore)(nil)