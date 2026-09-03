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

// ErrSecondFactorRequired is returned by Login when the account has
// at least one confirmed second-factor method enrolled (TOTP,
// WebAuthn/passkey, or both) — a correct password is no longer
// sufficient on its own. PendingToken must be presented to whichever
// Complete* function matches one of Methods. It is NOT a valid access
// or refresh token and proves nothing beyond "this caller already
// supplied a correct password for this user." Deliberately a struct
// type (not a plain sentinel), same reasoning as
// ErrOAuthEmailConflict — callers use errors.As to retrieve it.
//
// Renamed from the TOTP-only ErrTOTPRequired once WebAuthn/passkeys
// needed to gate login the same way — unifying under one method-
// agnostic pause state instead of a separate error per method the
// account might have enrolled.
type ErrSecondFactorRequired struct {
	PendingToken string
	// Methods lists which second-factor methods this account has
	// confirmed and enrolled — e.g. []string{"totp"},
	// []string{"webauthn"}, or both. The caller decides which to
	// prompt for (or offers a choice) based on this list.
	Methods []string
}

func (e *ErrSecondFactorRequired) Error() string {
	return "auth: a second factor is required to complete login"
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
	// ErrInvalidPendingLogin is returned by CompleteLoginWithTOTP or
	// CompleteLoginWithWebAuthn when pendingToken itself fails
	// verification (expired, tampered, or not a pending-login token
	// at all) — distinct from ErrInvalidTOTPCode/ErrInvalidWebAuthnResponse,
	// which cover a wrong code/response against an otherwise-valid
	// pending login.
	ErrInvalidPendingLogin = errors.New("auth: login session expired or invalid, please log in again")
	// ErrNoPasskeysEnrolled is returned by BeginWebAuthnLogin if the
	// account has no registered passkeys at all.
	ErrNoPasskeysEnrolled = errors.New("auth: no passkeys are registered for this account")
	// ErrInvalidWebAuthnResponse covers a failed ceremony verification
	// (bad signature, origin mismatch, stale/replayed challenge, or a
	// non-advancing signature counter suggesting a cloned
	// authenticator) — deliberately not differentiated further, same
	// enumeration-avoidance reasoning as ErrInvalidTOTPCode.
	ErrInvalidWebAuthnResponse = errors.New("auth: invalid or expired passkey response")
	// ErrInvalidCeremonyToken is returned when the encrypted ceremony
	// state handed back to FinishRegisterPasskey/CompleteLoginWithWebAuthn
	// fails to decrypt or has been tampered with.
	ErrInvalidCeremonyToken = errors.New("auth: passkey ceremony expired or invalid, please try again")
)
