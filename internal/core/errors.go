package core

import "errors"

var (
	// user errors
	ErrUserNotFound = errors.New("user not found")
	ErrUserExists   = errors.New("user alredy exists")
	ErrInvalidEmail = errors.New("incorrect email format")

	// password errors
	ErrPasswordToShort  = errors.New("password must be at least 8 characters")
	ErrPasswordTooLong  = errors.New("password execceds maximum lenght")
	ErrPasswordNoUpper  = errors.New("password must contain an uppercase letter")
	ErrPasswordNoLower  = errors.New("password must contain a lowercase letter")
	ErrPasswordNoNumber = errors.New("password must contain a number")

	// Rate limit errors
	ErrTooManyAttempts = errors.New("too many attempts, please try again later")

	// auth errors
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid or expired token")
	// token errors
	ErrInvalidSession  = errors.New("invalid or expired token")
	ErrSessionNotFound = errors.New("session not found")
	// Audit errors
	ErrAuditLogFailed = errors.New("Failed to write audit logs")
)

// validation error provides field level error details
type ValidationError struct {
	Field   string
	Message string
	Err     error
}

func (e *ValidationError) Error() string {
	return e.Field + ": " + e.Message
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}
