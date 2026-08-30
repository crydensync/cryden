package auth

import "errors"

var (
	ErrUserExists = errors.New("auth: user with this email already exists")
	// ErrInvalidCredentials is returned for both "no such user" and
	// "wrong password" — never differentiate in the returned error,
	// only in the audit log's metadata. Differentiating in the error
	// itself would let an attacker enumerate valid emails.
	ErrInvalidCredentials = errors.New("auth: invalid email or password")
	ErrRateLimited        = errors.New("auth: rate limit exceeded")
	// ErrAccountLocked is returned when an account has too many recent
	// failed login attempts. Distinct from ErrInvalidCredentials so
	// callers/UIs can show a different message — but note this DOES
	// leak that the account exists (unlike ErrInvalidCredentials).
	// That's an accepted tradeoff of lockout messaging in general.
	ErrAccountLocked = errors.New("auth: account temporarily locked due to failed login attempts")
)

// ErrOAuthEmailConflict is returned by LoginWithOAuth when the
// external identity's email matches an existing password-based
// account that isn't yet linked to this provider. Deliberately a
// struct type (not a plain sentinel) so Email and Provider survive
// being wrapped as this error travels up through api's HTTP layer —
// api needs both to render a useful "log in with password, then link
// Google" message. Callers should use errors.As to retrieve it.
//
// This is the deliberate choice: auto-linking on email match alone
// was rejected as an account-takeover vector, so this error exists to
// force the user through an explicit, confirmed linking step instead.
type ErrOAuthEmailConflict struct {
	Email    string
	Provider string
}

func (e *ErrOAuthEmailConflict) Error() string {
	return "auth: an account with this email already exists; log in with your password to link " + e.Provider
}

// ErrOAuthIdentityAlreadyLinked is returned by LinkOAuthIdentity when
// the external identity is already linked to a DIFFERENT user than
// the one requesting the link. Never silently re-point an existing
// link to a new account — that would let one user hijack a provider
// identity another user already claimed.
var ErrOAuthIdentityAlreadyLinked = errors.New("auth: this provider account is already linked to a different user")

// ErrTOTPRequired is returned by Login when the account has a
// confirmed TOTP secret — a correct password is no longer sufficient
// on its own. PendingToken must be presented to CompleteLoginWithTOTP
// together with the user's current code. It is NOT a valid access or
// refresh token and proves nothing beyond "this caller already
// supplied a correct password for this user." Deliberately a struct
// type (not a plain sentinel), same reasoning as
// ErrOAuthEmailConflict — callers use errors.As to retrieve it.
type ErrTOTPRequired struct {
	PendingToken string
}

func (e *ErrTOTPRequired) Error() string {
	return "auth: TOTP code required to complete login"
}

var (
	// ErrTOTPNotEnabled is returned when a caller acts as though an
	// account has TOTP enabled (e.g. CompleteLoginWithTOTP) but it
	// doesn't, or its enrollment was never confirmed.
	ErrTOTPNotEnabled     = errors.New("auth: TOTP is not enabled for this account")
	ErrTOTPAlreadyEnabled = errors.New("auth: TOTP is already enabled for this account")
	// ErrInvalidTOTPCode covers both a wrong code and an expired
	// pending-login token that failed at the code-check step —
	// deliberately not differentiated further than that, same
	// enumeration-avoidance reasoning as ErrInvalidCredentials.
	ErrInvalidTOTPCode = errors.New("auth: invalid or expired TOTP code")
	// ErrInvalidPendingLogin is returned by CompleteLoginWithTOTP when
	// pendingToken itself fails verification (expired, tampered, or
	// not a pending-login token at all) — distinct from
	// ErrInvalidTOTPCode, which covers a wrong code against an
	// otherwise-valid pending login.
	ErrInvalidPendingLogin = errors.New("auth: login session expired or invalid, please log in again")
)
