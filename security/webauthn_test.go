package security

import (
	"encoding/json"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/webauthn"
)

// fakeWebAuthnUser is a minimal webauthn.User for testing the
// provider in isolation, without pulling in store/auth types.
type fakeWebAuthnUser struct {
	id    []byte
	name  string
	creds []webauthn.Credential
}

func (u *fakeWebAuthnUser) WebAuthnID() []byte                         { return u.id }
func (u *fakeWebAuthnUser) WebAuthnName() string                       { return u.name }
func (u *fakeWebAuthnUser) WebAuthnDisplayName() string                { return u.name }
func (u *fakeWebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

const (
	testRPDisplayName = "Test App"
	testRPID          = "example.com"
	testRPOrigin      = "https://example.com"
)

// registerRealPasskey drives a full register ceremony through the
// provider using a real simulated authenticator (virtualwebauthn) —
// the only way to exercise CreateCredential's actual signature
// verification success path; any hand-built fake response can only
// ever test the rejection path.
func registerRealPasskey(t *testing.T, provider *GoWebAuthnProvider, user *fakeWebAuthnUser) (virtualwebauthn.Authenticator, virtualwebauthn.Credential, *webauthn.Credential) {
	t.Helper()
	rp := virtualwebauthn.RelyingParty{Name: testRPDisplayName, ID: testRPID, Origin: testRPOrigin}
	authenticator := virtualwebauthn.NewAuthenticator()
	vCred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	creation, session, err := provider.BeginRegistration(user)
	if err != nil {
		t.Fatalf("BeginRegistration failed: %v", err)
	}
	creationJSON, err := json.Marshal(creation)
	if err != nil {
		t.Fatalf("marshal creation options failed: %v", err)
	}

	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(creationJSON))
	if err != nil {
		t.Fatalf("ParseAttestationOptions failed: %v", err)
	}
	responseJSON := virtualwebauthn.CreateAttestationResponse(rp, authenticator, vCred, *attestationOptions)

	cred, err := provider.FinishRegistration(user, *session, []byte(responseJSON))
	if err != nil {
		t.Fatalf("FinishRegistration failed: %v", err)
	}

	authenticator.AddCredential(vCred)
	authenticator.Options.UserHandle = user.id
	return authenticator, vCred, cred
}

func TestGoWebAuthnProvider_RegisterCreatesAValidCredential(t *testing.T) {
	provider, err := NewGoWebAuthnProvider(testRPDisplayName, testRPID, []string{testRPOrigin})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	user := &fakeWebAuthnUser{id: []byte("user-1"), name: "raymondproguy@dev.com"}

	_, _, cred := registerRealPasskey(t, provider, user)
	if len(cred.ID) == 0 {
		t.Error("expected a non-empty credential ID")
	}
	if len(cred.PublicKey) == 0 {
		t.Error("expected a non-empty public key")
	}
}

func TestGoWebAuthnProvider_LoginRoundTrip(t *testing.T) {
	provider, err := NewGoWebAuthnProvider(testRPDisplayName, testRPID, []string{testRPOrigin})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	user := &fakeWebAuthnUser{id: []byte("user-1"), name: "raymondproguy@dev.com"}

	authenticator, vCred, cred := registerRealPasskey(t, provider, user)
	user.creds = append(user.creds, *cred)
	rp := virtualwebauthn.RelyingParty{Name: testRPDisplayName, ID: testRPID, Origin: testRPOrigin}

	// virtualwebauthn's simulated credential starts at counter 0 and
	// never auto-increments — unlike many real hardware authenticators,
	// which do. Bump it manually here to exercise the pass-through
	// path this test actually cares about: does FinishLogin correctly
	// surface whatever counter value the authenticator reports, so a
	// caller can persist it and detect a future non-advancing (cloned-
	// authenticator) value? A counter of 0 is itself a legitimate,
	// spec-allowed value (many platform authenticators never track
	// one at all), so asserting "must be nonzero" was simply wrong.
	vCred.Counter = 7

	assertion, session, err := provider.BeginLogin(user)
	if err != nil {
		t.Fatalf("BeginLogin failed: %v", err)
	}
	assertionJSON, err := json.Marshal(assertion)
	if err != nil {
		t.Fatalf("marshal assertion options failed: %v", err)
	}

	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(assertionJSON))
	if err != nil {
		t.Fatalf("ParseAssertionOptions failed: %v", err)
	}
	responseJSON := virtualwebauthn.CreateAssertionResponse(rp, authenticator, vCred, *assertionOptions)

	updatedCred, err := provider.FinishLogin(user, *session, []byte(responseJSON))
	if err != nil {
		t.Fatalf("FinishLogin failed: %v", err)
	}
	if updatedCred.Authenticator.SignCount != 7 {
		t.Errorf("expected the returned credential to carry the authenticator's reported counter (7), got %d", updatedCred.Authenticator.SignCount)
	}
}

func TestGoWebAuthnProvider_LoginRejectsGarbageResponse(t *testing.T) {
	provider, err := NewGoWebAuthnProvider(testRPDisplayName, testRPID, []string{testRPOrigin})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	user := &fakeWebAuthnUser{id: []byte("user-1"), name: "raymondproguy@dev.com"}

	_, _, cred := registerRealPasskey(t, provider, user)
	user.creds = append(user.creds, *cred)

	_, session, err := provider.BeginLogin(user)
	if err != nil {
		t.Fatalf("BeginLogin failed: %v", err)
	}

	_, err = provider.FinishLogin(user, *session, []byte(`{"not":"a real response"}`))
	if err == nil {
		t.Error("expected a garbage response to be rejected")
	}
}
