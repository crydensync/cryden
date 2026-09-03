module github.com/crydensync/cryden/v2

go 1.25.0

require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.12.3
	github.com/pquerna/otp v1.5.0
	golang.org/x/crypto v0.54.0
)

// github.com/pquerna/otp pulls in boombuler/barcode transitively (used
// internally for its optional QR-image helper, which this engine
// never calls — TOTP QR rendering is a presentation concern that
// belongs in a consuming app, not the engine). Go still needs it to
// build the otp package itself.
require github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
