package token

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
)

var (
	ErrInvalidToken = errors.New("token: refresh token not found or malformed")
	// ErrTokenReused is returned when an already-rotated (revoked) refresh
	// token is presented again — a signal of possible theft. The entire
	// session family has already been revoked by the time this is returned.
	ErrTokenReused = errors.New("token: refresh token reuse detected, session family revoked")
)

// HashToken returns the SHA-256 hex digest of a raw token. Only this
// hash is ever persisted — the raw token exists solely in the value
// returned to the caller at issue/rotation time.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// RefreshResult carries the newly issued raw refresh token and its
// backing session record.
type RefreshResult struct {
	RawToken string
	Session  store.Session
}

// Rotate validates a presented raw refresh token, detects reuse, and —
// if valid — issues a new token in the same session family while
// revoking the old one.
//
// Flow:
//  1. Hash the incoming raw token, look it up.
//  2. Not found -> ErrInvalidToken.
//  3. Found but already revoked -> reuse detected: revoke the entire
//     family, return ErrTokenReused. Caller is responsible for
//     recording the token_reuse_detected audit event — this function
//     only enforces the security invariant, it does not log.
//  4. Found and valid -> revoke the old row, issue + persist a new
//     token under the same family_id, return the new raw token.
func Rotate(
	ctx context.Context,
	sessions store.SessionStore,
	gen TokenGenerator,
	ids security.IDGenerator,
	rawToken string,
) (RefreshResult, error) {
	hash := HashToken(rawToken)

	existing, err := sessions.GetByTokenHash(ctx, hash)
	if err != nil {
		return RefreshResult{}, ErrInvalidToken
	}

	if existing.RevokedAt != nil {
		// Reuse of a token that was already rotated away — treat the
		// whole family as compromised. Return existing (not a zero
		// value) so the caller can attribute the audit event to the
		// correct user/family — losing that context here would make
		// the token_reuse_detected event useless for investigation.
		if revokeErr := sessions.RevokeFamily(ctx, existing.FamilyID); revokeErr != nil {
			return RefreshResult{Session: existing}, revokeErr
		}
		return RefreshResult{Session: existing}, ErrTokenReused
	}

	newRaw, err := gen.New()
	if err != nil {
		return RefreshResult{}, err
	}

	newID, err := ids.New()
	if err != nil {
		return RefreshResult{}, err
	}

	newSession := store.Session{
		ID:        newID,
		FamilyID:  existing.FamilyID,
		UserID:    existing.UserID,
		TokenHash: HashToken(newRaw),
		IP:        existing.IP,
		UserAgent: existing.UserAgent,
	}

	if err := sessions.RotateToken(ctx, existing.ID, newSession); err != nil {
		return RefreshResult{}, err
	}

	return RefreshResult{RawToken: newRaw, Session: newSession}, nil
}
