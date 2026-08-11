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

var _ store.AuditStore = (*AuditStore)(nil)
