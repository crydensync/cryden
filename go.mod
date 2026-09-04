module github.com/crydensync/cryden/v2

go 1.25.0

require (
	github.com/descope/virtualwebauthn v1.0.5
	github.com/go-webauthn/webauthn v0.18.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.12.3
	github.com/pquerna/otp v1.5.0
	github.com/redis/go-redis/v9 v9.22.0
	golang.org/x/crypto v0.55.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.0 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

// github.com/pquerna/otp pulls in boombuler/barcode transitively (used
// internally for its optional QR-image helper, which this engine
// never calls — TOTP QR rendering is a presentation concern that
// belongs in a consuming app, not the engine). Go still needs it to
// build the otp package itself.
require github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect

// github.com/redis/go-redis/v9 backs security.RedisRateLimiter, the
// distributed RateLimiter implementation. It is a direct dependency of
// the engine itself rather than of tests only: Redis is infrastructure
// the host app operates, in the same category as Postgres and lib/pq.
//
// github.com/descope/virtualwebauthn is a real dependency, but only
// ever imported from _test.go files and cmd/smoketest/webauthn-passkeys
// — it lets tests exercise the actual go-webauthn ceremony
// (BeginRegistration/CreateCredential/BeginLogin/ValidateLogin)
// against a real, cryptographically valid simulated authenticator
// response, rather than only testing the error paths a fake response
// would otherwise be limited to.
