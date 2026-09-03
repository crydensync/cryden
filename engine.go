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
	users         store.UserStore
	sessions      store.SessionStore
	audit         store.AuditStore
	verifications store.VerificationStore
	emailSender   notify.EmailSender
	oauth         store.OAuthStore
	totp          store.TOTPStore

	hasher           security.Hasher
	ids              security.IDGenerator
	rateLimiter      security.RateLimiter
	refreshGen       token.TokenGenerator
	jwtIssuer        *token.JWTIssuer
	pendingIssuer    *token.MFAPendingIssuer
	totpGen          security.TOTPGenerator
	encryptor        security.Encryptor
	totpIssuerName   string
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

	// TOTP-related dependencies are only constructed if Config.TOTP
	// is set — otherwise they stay nil, and Login/the TOTP facade
	// functions treat that as "feature not configured."
	var pendingIssuer *token.MFAPendingIssuer
	var encryptor security.Encryptor
	var totpGen security.TOTPGenerator
	if cfg.TOTP != nil {
		pendingIssuer, err = token.NewMFAPendingIssuer(cfg.JWTSecret)
		if err != nil {
			return nil, err
		}
		encryptor, err = security.NewAESGCMEncryptor(cfg.EncryptionKey)
		if err != nil {
			return nil, err
		}
		totpGen = security.NewPquernaTOTPGenerator()
	}

	return &Engine{
		users:            cfg.Users,
		sessions:         cfg.Sessions,
		audit:            cfg.Audit,
		verifications:    cfg.Verifications,
		emailSender:      cfg.EmailSender,
		oauth:            cfg.OAuth,
		totp:             cfg.TOTP,
		hasher:           hasher,
		ids:              security.NewUUIDv7Generator(),
		rateLimiter:      security.NewInMemoryRateLimiter(cfg.RateLimitAttempts, cfg.RateLimitWindow),
		refreshGen:       refreshGen,
		jwtIssuer:        jwtIssuer,
		pendingIssuer:    pendingIssuer,
		totpGen:          totpGen,
		encryptor:        encryptor,
		totpIssuerName:   cfg.TOTPIssuerName,
		log:              cfg.Logger,
		lockoutThreshold: cfg.LockoutThreshold,
		lockoutDuration:  cfg.LockoutDuration,
	}, nil
}
