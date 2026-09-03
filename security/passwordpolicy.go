package security

import "unicode"

// PasswordPolicy configures which passwords SignUp/ChangePassword
// accept. Plain configuration data with a validation method, not a
// pluggable interface like the rest of this package — there's nothing
// to swap out here, just numbers and booleans.
//
// Violation codes returned by Validate are stable, machine-readable
// strings ("min_length", not "Password must be at least 8
// characters") — the engine doesn't own UI copy or localization
// anywhere else (EmailSender/MagicLinkSender don't get pre-written
// email bodies either), so it doesn't start here.
type PasswordPolicy struct {
	// MinLength defaults to 8 if the whole PasswordPolicy is left as
	// the zero value (detected via MaxLength == 0 — see
	// applyDefaults). NIST 800-63B guidance is length matters far
	// more than forced complexity rules, which is why the default
	// ships with no character-class requirements at all.
	MinLength int
	// MaxLength defaults to 72 — bcrypt's own real limit. Without an
	// explicit check here, a password over that silently hits a raw
	// bcrypt library error at hash time instead of a clean policy
	// violation.
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSymbol    bool
}

// DefaultPasswordPolicy is applied automatically whenever
// Config.PasswordPolicy is left as the zero value — password
// strength isn't an optional bonus feature the way TOTP/WebAuthn are,
// so unlike those, this has no "unconfigured means off" state.
var DefaultPasswordPolicy = PasswordPolicy{
	MinLength: 8,
	MaxLength: 72,
}

// Validate checks password against p, returning every violated rule
// at once (as stable string codes) rather than stopping at the first
// failure — so a caller can show "needs 8+ characters AND a number"
// together instead of making someone fix one problem, resubmit, and
// discover the next one.
func (p PasswordPolicy) Validate(password string) []string {
	var violations []string

	if len(password) < p.MinLength {
		violations = append(violations, "min_length")
	}
	if p.MaxLength > 0 && len(password) > p.MaxLength {
		violations = append(violations, "max_length")
	}
	if p.RequireUppercase && !containsRune(password, unicode.IsUpper) {
		violations = append(violations, "require_uppercase")
	}
	if p.RequireLowercase && !containsRune(password, unicode.IsLower) {
		violations = append(violations, "require_lowercase")
	}
	if p.RequireDigit && !containsRune(password, unicode.IsDigit) {
		violations = append(violations, "require_digit")
	}
	if p.RequireSymbol && !containsRune(password, isSymbolRune) {
		violations = append(violations, "require_symbol")
	}

	return violations
}

func containsRune(s string, match func(rune) bool) bool {
	for _, r := range s {
		if match(r) {
			return true
		}
	}
	return false
}

func isSymbolRune(r rune) bool {
	return unicode.IsPunct(r) || unicode.IsSymbol(r)
}
