package cryden

import (
	"time"

	"github.com/crydensync/cryden/v2/logger"
	"github.com/crydensync/cryden/v2/notify"
	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/token"
)

// Engine holds every wired-up dependency needed by the public facade
// functions (SignUp, Login, etc. in cryden.go). Consumers never
// construct this directly — always via New(cfg).
type Engine struct {
	users           store.UserStore
	sessions        store.SessionStore
	audit           store.AuditStore
	verifications   store.VerificationStore
	emailSender     notify.EmailSender
	oauth           store.OAuthStore
	totp            store.TOTPStore
	webauthn        store.WebAuthnCredentialStore
	magicLinkSender notify.MagicLinkSender
	recoveryCodes   store.RecoveryCodeStore

	hasher           security.Hasher
	ids              security.IDGenerator
	rateLimiter      security.RateLimiter
	refreshGen       token.TokenGenerator
	jwtIssuer        *token.JWTIssuer
	pendingIssuer    *token.MFAPendingIssuer
	totpGen          security.TOTPGenerator
	encryptor        security.Encryptor
	totpIssuerName   string
	webauthnProvider security.WebAuthnProvider
	webauthnRPID     string
	log              logger.Logger
	lockoutThreshold int
	lockoutDuration  time.Duration
}

// New validates cfg, applies defaults for unset tuning knobs, and
// wires an Engine. Fails loudly (returns an error, never a silently
// insecure default) if JWTSecret or any required store is missing.
func New(cfg Config) (*Engine, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.applyDefaults()

	hasher, err := security.NewBcryptHasher(cfg.BcryptCost)
	if err != nil {
		return nil, err
	}

	refreshGen, err := token.NewCryptoRandTokenGenerator(cfg.RefreshTokenByteLength)
	if err != nil {
		return nil, err
	}

	jwtIssuer, err := token.NewJWTIssuer(cfg.JWTSecret, cfg.AccessTokenTTL)
	if err != nil {
		return nil, err
	}

	// pendingIssuer and encryptor are shared infrastructure for BOTH
	// second-factor methods: pendingIssuer gates Login the same way
	// regardless of which method an account has, and encryptor is
	// reused as-is to encrypt WebAuthn ceremony state the same way it
	// encrypts TOTP secrets — one EncryptionKey, two consumers, no
	// separate WebAuthn-specific secret to configure. Constructed if
	// EITHER Config.TOTP or Config.WebAuthn is set; nil otherwise.
	var pendingIssuer *token.MFAPendingIssuer
	var encryptor security.Encryptor
	var totpGen security.TOTPGenerator
	var webauthnProvider security.WebAuthnProvider
	if cfg.TOTP != nil || cfg.WebAuthn != nil {
		pendingIssuer, err = token.NewMFAPendingIssuer(cfg.JWTSecret)
		if err != nil {
			return nil, err
		}
		encryptor, err = security.NewAESGCMEncryptor(cfg.EncryptionKey)
		if err != nil {
			return nil, err
		}
	}
	if cfg.TOTP != nil {
		totpGen = security.NewPquernaTOTPGenerator()
	}
	if cfg.WebAuthn != nil {
		webauthnProvider, err = security.NewGoWebAuthnProvider(cfg.WebAuthnRPDisplayName, cfg.WebAuthnRPID, cfg.WebAuthnRPOrigins)
		if err != nil {
			return nil, err
		}
	}

	return &Engine{
		users:            cfg.Users,
		sessions:         cfg.Sessions,
		audit:            cfg.Audit,
		verifications:    cfg.Verifications,
		emailSender:      cfg.EmailSender,
		oauth:            cfg.OAuth,
		totp:             cfg.TOTP,
		webauthn:         cfg.WebAuthn,
		magicLinkSender:  cfg.MagicLinkSender,
		recoveryCodes:    cfg.RecoveryCodes,
		hasher:           hasher,
		ids:              security.NewUUIDv7Generator(),
		rateLimiter:      security.NewInMemoryRateLimiter(cfg.RateLimitAttempts, cfg.RateLimitWindow),
		refreshGen:       refreshGen,
		jwtIssuer:        jwtIssuer,
		pendingIssuer:    pendingIssuer,
		totpGen:          totpGen,
		encryptor:        encryptor,
		totpIssuerName:   cfg.TOTPIssuerName,
		webauthnProvider: webauthnProvider,
		webauthnRPID:     cfg.WebAuthnRPID,
		log:              cfg.Logger,
		lockoutThreshold: cfg.LockoutThreshold,
		lockoutDuration:  cfg.LockoutDuration,
	}, nil
}
