package token

import (
	"context"
	"testing"

	"github.com/crydensync/cryden/v2/security"
	"github.com/crydensync/cryden/v2/store"
	"github.com/crydensync/cryden/v2/store/memory"
)

func setupRotationTest(t *testing.T) (context.Context, *memory.SessionStore, TokenGenerator, security.IDGenerator) {
	t.Helper()
	gen, err := NewCryptoRandTokenGenerator(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return context.Background(), memory.NewSessionStore(), gen, security.NewUUIDv7Generator()
}

func TestRotate_ValidTokenIssuesNewOne(t *testing.T) {
	ctx, sessions, gen, ids := setupRotationTest(t)

	rawOriginal, _ := gen.New()
	sessionID, _ := ids.New()
	original := store.Session{
		ID:        sessionID,
		FamilyID:  sessionID,
		UserID:    "user-1",
		TokenHash: HashToken(rawOriginal),
	}
	if err := sessions.Create(ctx, original); err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	result, err := Rotate(ctx, sessions, gen, ids, rawOriginal)
	if err != nil {
		t.Fatalf("expected successful rotation, got error: %v", err)
	}
	if result.RawToken == rawOriginal {
		t.Error("expected a new raw token, got the same one back")
	}
	if result.Session.FamilyID != sessionID {
		t.Error("expected new session to retain the original family_id")
	}

	// The old session should now be revoked.
	oldSession, err := sessions.GetByID(ctx, sessionID)
	if err != nil {
		t.Fatalf("unexpected error fetching old session: %v", err)
	}
	if oldSession.RevokedAt == nil {
		t.Error("expected old session to be revoked after rotation")
	}
}

func TestRotate_UnknownTokenRejected(t *testing.T) {
	ctx, sessions, gen, ids := setupRotationTest(t)

	_, err := Rotate(ctx, sessions, gen, ids, "never-issued-token")
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestRotate_ReuseDetectionRevokesEntireFamily(t *testing.T) {
	ctx, sessions, gen, ids := setupRotationTest(t)

	rawOriginal, _ := gen.New()
	sessionID, _ := ids.New()
	original := store.Session{
		ID:        sessionID,
		FamilyID:  sessionID,
		UserID:    "user-1",
		TokenHash: HashToken(rawOriginal),
	}
	sessions.Create(ctx, original)

	// First rotation — legitimate, succeeds.
	firstResult, err := Rotate(ctx, sessions, gen, ids, rawOriginal)
	if err != nil {
		t.Fatalf("expected first rotation to succeed: %v", err)
	}

	// Reusing the now-revoked original token — this is the theft signal.
	reuseResult, err := Rotate(ctx, sessions, gen, ids, rawOriginal)
	if err != ErrTokenReused {
		t.Fatalf("expected ErrTokenReused, got %v", err)
	}
	// Even on the error path, the caller needs UserID/FamilyID to log
	// the audit event correctly — verify that context wasn't lost.
	if reuseResult.Session.UserID != "user-1" {
		t.Error("expected reuse result to still carry the correct UserID for audit logging")
	}
	if reuseResult.Session.FamilyID != sessionID {
		t.Error("expected reuse result to still carry the correct FamilyID for audit logging")
	}

	// The legitimately-rotated-forward token must ALSO be dead now —
	// this is the entire point of family revocation on reuse detection.
	_, err = Rotate(ctx, sessions, gen, ids, firstResult.RawToken)
	if err == nil {
		t.Error("expected the legitimately rotated token to also be revoked after reuse detection on the family")
	}
}

func TestRotate_RevokedTokenNotInFamilyStillDetectedAsReuse(t *testing.T) {
	// Sanity check: rotating a token twice in a row (A -> B -> C) then
	// replaying A must still trigger reuse detection, not just replaying
	// the immediately-prior token.
	ctx, sessions, gen, ids := setupRotationTest(t)

	rawA, _ := gen.New()
	sessionID, _ := ids.New()
	sessions.Create(ctx, store.Session{
		ID: sessionID, FamilyID: sessionID, UserID: "user-1", TokenHash: HashToken(rawA),
	})

	resultB, err := Rotate(ctx, sessions, gen, ids, rawA)
	if err != nil {
		t.Fatalf("rotation A->B failed: %v", err)
	}
	_, err = Rotate(ctx, sessions, gen, ids, resultB.RawToken)
	if err != nil {
		t.Fatalf("rotation B->C failed: %v", err)
	}

	// Replay the original (twice-stale) token A.
	_, err = Rotate(ctx, sessions, gen, ids, rawA)
	if err != ErrTokenReused {
		t.Errorf("expected ErrTokenReused replaying a twice-stale token, got %v", err)
	}
}
