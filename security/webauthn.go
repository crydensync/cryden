package security

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnProvider defines the WebAuthn (passkey) registration and
// login ceremonies. Unlike TOTPGenerator and Encryptor, this
// interface exposes go-webauthn's own types directly (SessionData,
// webauthn.Credential, protocol.CredentialCreation/Assertion) rather
// than hiding them behind primitive strings — a WebAuthn ceremony is
// too rich to flatten into a small custom vocabulary without
// reinventing a parallel API for no real benefit. The public cryden
// facade still deals in plain []byte JSON at its own boundary; these
// richer types stay internal to the engine.
//
// v2 ships one implementation: GoWebAuthnProvider, wrapping
// github.com/go-webauthn/webauthn — a WebAuthn ceremony has enough
// real attack surface (origin/RP-ID validation, attestation formats,
// signature-counter checks for cloned authenticators, challenge
// replay) that a hand-rolled implementation would be a serious
// security liability, unlike TOTP where hand-rolling was a realistic
// option we chose not to take.
type WebAuthnProvider interface {
	BeginRegistration(user webauthn.User) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	// FinishRegistration parses responseJSON (the raw JSON body from
	// the browser's navigator.credentials.create() call) and verifies
	// it against session.
	FinishRegistration(user webauthn.User, session webauthn.SessionData, responseJSON []byte) (*webauthn.Credential, error)
	BeginLogin(user webauthn.User) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	// FinishLogin parses responseJSON (the raw JSON body from the
	// browser's navigator.credentials.get() call) and verifies it
	// against session, returning the matched, updated Credential —
	// callers must persist its new SignCount.
	FinishLogin(user webauthn.User, session webauthn.SessionData, responseJSON []byte) (*webauthn.Credential, error)
}

// GoWebAuthnProvider is the v2 WebAuthnProvider implementation.
type GoWebAuthnProvider struct {
	wa *webauthn.WebAuthn
}

// NewGoWebAuthnProvider constructs a provider for the given relying
// party. rpID is the actual domain the credentials are bound to
// (e.g. "yourapp.com") — unlike TOTPIssuerName, this is a real
// security parameter, not cosmetic: a credential registered against
// one RP ID will never validate against another.
func NewGoWebAuthnProvider(rpDisplayName, rpID string, rpOrigins []string) (*GoWebAuthnProvider, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     rpOrigins,
	})
	if err != nil {
		return nil, err
	}
	return &GoWebAuthnProvider{wa: wa}, nil
}

func (p *GoWebAuthnProvider) BeginRegistration(user webauthn.User) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return p.wa.BeginRegistration(user)
}

func (p *GoWebAuthnProvider) FinishRegistration(user webauthn.User, session webauthn.SessionData, responseJSON []byte) (*webauthn.Credential, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBytes(responseJSON)
	if err != nil {
		return nil, err
	}
	return p.wa.CreateCredential(user, session, parsed)
}

func (p *GoWebAuthnProvider) BeginLogin(user webauthn.User) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return p.wa.BeginLogin(user)
}

func (p *GoWebAuthnProvider) FinishLogin(user webauthn.User, session webauthn.SessionData, responseJSON []byte) (*webauthn.Credential, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(responseJSON)
	if err != nil {
		return nil, err
	}
	return p.wa.ValidateLogin(user, session, parsed)
}

var _ WebAuthnProvider = (*GoWebAuthnProvider)(nil)
