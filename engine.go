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

	hasher           security.Hasher
	ids              security.IDGenerator
	rateLimiter      security.RateLimiter
	refreshGen       token.TokenGenerator
	jwtIssuer        *token.JWTIssuer
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

	return &Engine{
		users:            cfg.Users,
		sessions:         cfg.Sessions,
		audit:            cfg.Audit,
		verifications:    cfg.Verifications,
		emailSender:      cfg.EmailSender,
		hasher:           hasher,
		ids:              security.NewUUIDv7Generator(),
		rateLimiter:      security.NewInMemoryRateLimiter(cfg.RateLimitAttempts, cfg.RateLimitWindow),
		refreshGen:       refreshGen,
		jwtIssuer:        jwtIssuer,
		log:              cfg.Logger,
		lockoutThreshold: cfg.LockoutThreshold,
		lockoutDuration:  cfg.LockoutDuration,
	}, nil
}
