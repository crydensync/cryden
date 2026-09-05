package token

import (
	"context"
	"fmt"
	"sort"
)

// ClaimsProvider lets a host app attach its own data to every access
// token the engine issues. The engine calls it once per access token —
// on every completed login and again on every refresh — and merges what
// it returns into the token's claims alongside the registered ones the
// engine sets itself.
//
// It exists because the alternative is a round trip: without it, a host
// whose API gateway needs a role or a tenant ID has to look the user up
// again on every request, having just been handed a signed statement
// about that exact user. A claim in the token is that lookup, cached for
// the token's lifetime and signed.
//
// The contract, in full:
//
//   - Reserved claim names are refused, not overwritten. Returning any
//     of ReservedClaimNames() fails the whole issue with
//     ErrReservedClaim, and therefore fails the login or refresh that
//     asked for it. "sub" is the one that matters most: Verify reads the
//     user ID out of it, so a provider able to set it would be a
//     provider able to mint a token for somebody else.
//   - An error fails the token. Not "issues a token without the extra
//     claims" — see the note on failing closed below.
//   - Values must marshal to JSON. Strings, numbers, bools, and slices
//     or maps of those. A channel or a func fails the issue.
//   - It is called on the hot path, synchronously, holding up a login.
//     If it queries a database, that query is now part of every login and
//     every refresh. Cache accordingly.
//
// On failing closed: a provider error takes the login down with it,
// which is the opposite of how security.BreachedPasswordChecker behaves
// two packages over — a checker error there lets the signup through. The
// difference is what the two produce. A breach check is a restriction,
// and failing open on a restriction lets a legitimate user in. Claims are
// authorization data, and failing open on those issues a credential
// carrying less authority than it should, into a system that may well
// read the absence of a claim as permission rather than denial. The
// engine will not guess which; it declines to issue the token.
type ClaimsProvider interface {
	AccessTokenClaims(ctx context.Context, userID string) (map[string]any, error)
}

// ClaimsFunc adapts a plain function to ClaimsProvider, for the common
// case where the host's implementation is one lookup and needs no state
// of its own:
//
//	cfg.AccessTokenClaims = token.ClaimsFunc(func(ctx context.Context, userID string) (map[string]any, error) {
//		role, err := db.RoleOf(ctx, userID)
//		if err != nil {
//			return nil, err
//		}
//		return map[string]any{"role": role}, nil
//	})
type ClaimsFunc func(ctx context.Context, userID string) (map[string]any, error)

func (f ClaimsFunc) AccessTokenClaims(ctx context.Context, userID string) (map[string]any, error) {
	return f(ctx, userID)
}

var _ ClaimsProvider = ClaimsFunc(nil)

// reservedClaims are the seven registered names from RFC 7519 §4.1. All
// seven are refused, including the four the engine does not currently
// set: a host putting its own meaning on "aud" or "iss" today would find
// that meaning silently colliding with the engine's the day the engine
// starts setting one, and "nbf" and "jti" decide whether a token is
// valid at all. Refusing the whole registered set is a rule that stays
// true; refusing only what is in use today is a rule with an expiry date.
//
// Matching is case-sensitive, because JSON object keys are: "SUB" is a
// different claim, and an inert one, so nothing needs saving from it.
var reservedClaims = map[string]struct{}{
	"iss": {},
	"sub": {},
	"aud": {},
	"exp": {},
	"nbf": {},
	"iat": {},
	"jti": {},
}

// ReservedClaimNames returns the claim names a ClaimsProvider may not
// set, sorted. Returned fresh each call so a caller cannot edit the set
// the check itself reads.
func ReservedClaimNames() []string {
	names := make([]string, 0, len(reservedClaims))
	for name := range reservedClaims {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// IsReservedClaim reports whether name is one the engine keeps for
// itself. Useful in a host's own tests, so a provider returning a
// forbidden name is caught there rather than by a failed login.
func IsReservedClaim(name string) bool {
	_, ok := reservedClaims[name]
	return ok
}

// checkExtraClaims validates the whole map before anything is merged, so
// a rejected claim leaves no half-built token behind: either every claim
// the provider returned is acceptable or none of them are applied.
func checkExtraClaims(extra map[string]any) error {
	for name := range extra {
		if name == "" {
			return ErrEmptyClaimName
		}
		if IsReservedClaim(name) {
			return fmt.Errorf("%w: %q", ErrReservedClaim, name)
		}
	}
	return nil
}
