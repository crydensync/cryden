package memory

import (
	"context"
	"sync"
	"time"

	"github.com/crydensync/cryden/v2/store"
)

// AuditStore is an in-memory store.AuditStore implementation for
// tests and local experimentation only.
type AuditStore struct {
	mu     sync.Mutex
	events []store.AuditEvent
}

func NewAuditStore() *AuditStore {
	return &AuditStore{}
}

func (s *AuditStore) Record(ctx context.Context, event store.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	event.CreatedAt = time.Now()
	s.events = append(s.events, event)
	return nil
}

func (s *AuditStore) ListByUser(ctx context.Context, userID string, limit int) ([]store.AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.AuditEvent
	for i := len(s.events) - 1; i >= 0 && len(out) < limit; i-- {
		if s.events[i].UserID == userID {
			out = append(out, s.events[i])
		}
	}
	return out, nil
}

func (s *AuditStore) SearchByType(ctx context.Context, eventType store.AuditEventType, limit int) ([]store.AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.AuditEvent
	for i := len(s.events) - 1; i >= 0 && len(out) < limit; i-- {
		if s.events[i].Type == eventType {
			out = append(out, s.events[i])
		}
	}
	return out, nil
}

// CountByType counts the events recorded at or after since, by type.
// Types absent from the window are absent from the map — see
// store.AuditStore for the contract this satisfies.
func (s *AuditStore) CountByType(ctx context.Context, since time.Time) (map[store.AuditEventType]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts := make(map[store.AuditEventType]int)
	for _, e := range s.events {
		// !Before rather than After: "at or after since", so an event
		// recorded on the boundary instant is inside the window.
		if !e.CreatedAt.Before(since) {
			counts[e.Type]++
		}
	}
	return counts, nil
}

var _ store.AuditStore = (*AuditStore)(nil)
