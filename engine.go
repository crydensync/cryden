package cryden

import (
	"context"
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
	breachChecker   security.BreachedPasswordChecker
	geolocator      security.IPGeolocator
	passwordPolicy  security.PasswordPolicy
	anomalies       store.AnomalyStore

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

	anomalyThresholds  security.AnomalyThresholds
	stuffingThresholds security.CredentialStuffingThresholds
}

// New validates cfg, applies defaults for unset tuning knobs, and
// wires an Engine. Fails loudly (returns an error, never a silently
// insecure default) if JWTSecret or any required store is missing.
func New(cfg Config) (*Engine, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.applyDefaults()

	// A host-supplied hasher wins outright; bcrypt at the configured
	// cost is built only when none was given. Either way the result is
	// wrapped in a MultiHasher, unconditionally: dispatch costs nothing
	// (a stored hash names its own algorithm) and it is what keeps hashes
	// written before a switch verifiable after it. Nothing in auth/ can
	// tell the difference — every call site holds security.Hasher.
	primary := cfg.Hasher
	if primary == nil {
		bcryptHasher, err := security.NewBcryptHasher(cfg.BcryptCost)
		if err != nil {
			return nil, err
		}
		primary = bcryptHasher
	}
	hasher := security.NewMultiHasher(primary)

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

	// A host-supplied limiter wins outright; the in-process default is
	// built from the two tuning knobs only when none was given. Which
	// one is in play is not a detail the rest of the engine can see —
	// every call site holds the security.RateLimiter interface, so
	// swapping the counter's home never reaches auth/.
	rateLimiter := cfg.RateLimiter
	if rateLimiter == nil {
		rateLimiter = security.NewInMemoryRateLimiter(cfg.RateLimitAttempts, cfg.RateLimitWindow)
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
		breachChecker:    cfg.BreachedPasswordChecker,
		geolocator:       cfg.Geolocator,
		passwordPolicy:   cfg.PasswordPolicy,
		anomalies:        cfg.Anomalies,
		hasher:           hasher,
		ids:              security.NewUUIDv7Generator(),
		rateLimiter:      rateLimiter,
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

		anomalyThresholds:  cfg.AnomalyThresholds,
		stuffingThresholds: cfg.CredentialStuffingThresholds,
	}, nil
}

// logFor binds ctx to the configured Logger for the duration of one
// facade call. Everything the facade delegates to — auth/, session/,
// token/ — takes a plain logger.Logger and has no context to pass at
// its 91 log call sites, so the binding happens once here, at the only
// layer holding both. A Logger that does not implement
// logger.ContextLogger, the ConsoleJSONLogger default included, comes
// back unchanged and never notices.
func (e *Engine) logFor(ctx context.Context) logger.Logger {
	return logger.ForContext(ctx, e.log)
}
