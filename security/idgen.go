package security

import "github.com/google/uuid"

// IDGenerator defines ID generation for users, sessions, audit events,
// and session families. v2 ships one implementation: UUIDv7Generator.
// UUIDv7 is time-ordered (sortable, index-friendly) without leaking
// a predictable sequence the way time.Now().UnixNano() would.
type IDGenerator interface {
	New() (string, error)
}

// UUIDv7Generator is the v1 IDGenerator implementation.
type UUIDv7Generator struct{}

func NewUUIDv7Generator() *UUIDv7Generator {
	return &UUIDv7Generator{}
}

func (g *UUIDv7Generator) New() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
