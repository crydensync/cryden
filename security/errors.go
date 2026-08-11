package security

import "errors"

var (
	ErrInvalidBcryptCost = errors.New("security: bcrypt cost out of valid range")
)
