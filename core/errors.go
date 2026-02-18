package core

import "errors"

var (
	// user errors
	ErrUserNotFound   = errors.New("user not found")
	ErrUserExists      = errors.New("user alredy exists")
	ErrInvalidEmail   = errors.New("incorrect email format")

	// password errors
  ErrPasswordToShort   = errors.New("password must be at least 8 characters")
	ErrPasswordTooLong   = errors.New("password execceds maximum lenght")
	ErrPasswordNoUpper   = errors.New("password must contain an uppercase letter")
	ErrPasswordNoLower   = errors.New("password must contain a lowercase letter")
	ErrPasswordNoNumber  = errors.New("password must contain a number")

  // auth errors
  ErrInvalidCredentials	= errors.New("invalid email or password")

	// token errors
	ErrInvalidSession    = errors.New("invalid or expired token")
	ErrSessionNotFound   = errors.New("session not found")
)

// validation error provides field level error details
type ValidationError struct {
	Fieled   string
  Message  string
	Err      error
}

func (e *ValidationError) Error() string {
	return e.Fieled + ": " + e.Message
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}
