package security

import (
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPGenerator defines TOTP (RFC 6238) secret generation and code
// validation. v2 ships one implementation, PquernaTOTPGenerator,
// wrapping github.com/pquerna/otp rather than hand-rolling RFC 6238
// against the stdlib the way Hasher/RateLimiter/IDGenerator do —
// TOTP has enough real edge cases (base32 padding, clock-skew
// windows, Google-Authenticator-compatible defaults) that a
// battle-tested implementation is worth the one dependency.
type TOTPGenerator interface {
	// NewSecret generates a fresh base32 secret for a new enrollment.
	// issuer and accountName are purely presentational — they're
	// encoded into the returned otpauth:// URL so an authenticator
	// app can label the entry, and are never persisted by the engine.
	// accountName should be the user's email.
	NewSecret(issuer, accountName string) (secret string, otpauthURL string, err error)
	// Validate checks code against secret at time t, allowing the
	// standard ±1 step (30s) clock-skew tolerance. t is an explicit
	// parameter (not time.Now() internally) so callers/tests can
	// exercise skew behavior deterministically.
	Validate(secret, code string, t time.Time) bool
}

// PquernaTOTPGenerator is the v2 TOTPGenerator implementation.
type PquernaTOTPGenerator struct{}

func NewPquernaTOTPGenerator() *PquernaTOTPGenerator {
	return &PquernaTOTPGenerator{}
}

func (g *PquernaTOTPGenerator) NewSecret(issuer, accountName string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

func (g *PquernaTOTPGenerator) Validate(secret, code string, t time.Time) bool {
	valid, _ := totp.ValidateCustom(code, secret, t, totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1, // Google-Authenticator-compatible; see pquerna/otp#55
	})
	return valid
}

var _ TOTPGenerator = (*PquernaTOTPGenerator)(nil)
