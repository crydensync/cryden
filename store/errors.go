package store

import "errors"

var (
	// ErrNotFound is returned by any store implementation when a
	// lookup (by ID, email, or token hash) finds no matching record.
	ErrNotFound = errors.New("store: record not found")
	// ErrSessionNotOwned is returned when a caller-supplied userID does
	// not match a session's actual owner. Shared here (rather than in
	// auth or session) so neither package needs to depend on the other
	// just to reference this error.
	ErrSessionNotOwned = errors.New("store: session does not belong to this user")
)
