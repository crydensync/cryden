package core

import (
	"strings"
	"unicode"
)

// ValidateEmail checks if email is valid
func ValidateEmail(email string) error {
	// Trim spaces
	email = strings.TrimSpace(email)
	// Check if empty
	if email == "" {
		return &ValidationError{
			Field:   "email",
			Message: "email cannot be empty",
			Err:     ErrInvalidEmail,
		}
	}
	// Check lenght (RFC 5321)
	if len(email) > 254 {
		return &ValidationError{
			Field:   "email",
			Message: "email too long",
			Err:     ErrInvalidEmail,
		}
	}
	// Must contail "@"
	if !strings.Contains(email, "@") {
		return &ValidationError{
			Field:   "email",
			Message: "email must contain @ symbol",
			Err:     ErrInvalidEmail,
		}
	}
	// Split local and domain part
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return &ValidationError{
			Field:   "email",
			Message: "email must contain exactly on@ symbol",
		}
	}
	local, domain := parts[0], parts[1]

	// Check local part not empty
	if local == "" {
		return &ValidationError{
			Field:   "email",
			Message: "email local part cannot be empty",
			Err:     ErrInvalidEmail,
		}
	}

	// Check domain not empty
	if domain == "" {
		return &ValidationError{
			Field:   "email",
			Message: "email domain connot be empty",
			Err:     ErrInvalidEmail,
		}
	}

	// Domain must contain . dot
	if !strings.Contains(domain, ".") {
		return &ValidationError{
			Field:   "email",
			Message: "email must contain a . dot",
			Err:     ErrInvalidEmail,
		}
	}

	return nil
}

// PasswordPolicy defines rules for passwords
type PasswordPolicy struct {
	MinLenght      int
	MaxLenght      int
	RequireUpper   bool
	RequireLower   bool
	RequireNumber  bool
	RequireSpecial bool
}

// DefaultPasswordPolicy returns sensible defauls
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLenght:      8,
		MaxLenght:      72, //bcrypt limit
		RequireUpper:   true,
		RequireLower:   true,
		RequireNumber:  true,
		RequireSpecial: false, // for now test MVP
	}
}

func ValidatePassword(password string, policy PasswordPolicy) error {
    // Check length
    if len(password) < policy.MinLenght {
        return &ValidationError{
            Field:   "password",
            Message: "password too short",
            Err:     ErrPasswordTooShort,
        }
    }

    if len(password) > policy.MaxLenght {
        return &ValidationError{
            Field:   "password",
            Message: "password too long",
            Err:     ErrPasswordTooLong,
        }
    }

    // Check character requirements
    var hasUpper, hasLower, hasNumber bool
    for _, char := range password {
        switch {
        case unicode.IsUpper(char):
            hasUpper = true
        case unicode.IsLower(char):
            hasLower = true
        case unicode.IsDigit(char):
            hasNumber = true
        }
    }

    if policy.RequireUpper && !hasUpper {
        return &ValidationError{
            Field:   "password",
            Message: "password must contain uppercase letter",
            Err:     ErrPasswordNoUpper,
        }
    }

    if policy.RequireLower && !hasLower {
        return &ValidationError{
            Field:   "password",
            Message: "password must contain lowercase letter",
            Err:     ErrPasswordNoLower,
        }
    }

    if policy.RequireNumber && !hasNumber {
        return &ValidationError{
            Field:   "password",
            Message: "password must contain number",
            Err:     ErrPasswordNoNumber,
        }
    }

    return nil
}

/*
// ValidatePassword checks password against policy
func ValidatePassword(password string, policy PasswordPolicy) error {
	// Check lenght
	if len(password) < policy.MinLenght {
		return &ValidationError{
			Field:   "password",
			Message: "password too short",
			Err:     ErrPasswordTooShort,
		}
	}

	if len(password) > policy.MaxLenght {
		return &ValidationError{
			Field:   "password",
			Message: "password too long",
			Err:     ErrPasswordTooLong,
		}
	}

	// Check character requirement
	var hasUpper, hasLower, hasNumber bool // hasSpecail
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasNumber = true
			//case unicode.IsPunct(char) || unicode.IsSymbol(char):
			//hasSpecail = true
		}
	}

	if policy.RequireUpper && !hasUpper {
		return &ValidationError{
			Field:   "password",
			Message: "password must contain uppercase ",
			Err:     ErrPasswordNoUpper,
		}
	}

	if policy.RequireLower && !hasLower {
		return &ValidationError{
			Field:   "password",
			Message: "password must contain lowercase",
			Err:     ErrPasswordNoLower,
		}
	}

	if policy.RequireNumber && !hasNumber {
		return &ValidationError{
			Field:   "password",
			Message: "password must contain number",
		}
	}

	return nil
}
*/
