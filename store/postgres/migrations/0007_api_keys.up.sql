-- 0007_api_keys.up.sql

CREATE TABLE api_keys (
    id           UUID PRIMARY KEY,
    -- ON DELETE CASCADE, not SET NULL: a key with no owner would
    -- authenticate as nobody, so it must die with the account. That is
    -- the opposite of audit_events/login_attempts, whose rows are
    -- evidence about a deleted account and keep their value without it.
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Presentational label ('CI deploy bot'), and the non-secret
    -- fragment of the key ('ck_a1b2c3d4') a management UI shows in
    -- place of the key. Neither is unique; neither gates anything.
    name         TEXT NOT NULL DEFAULT '',
    prefix       TEXT NOT NULL DEFAULT '',
    -- SHA-256 of the whole raw key, not bcrypt. A key is crypto/rand
    -- output rather than a human-chosen secret, so there is nothing for
    -- a slow hash to defend against — and this column is read on every
    -- machine request, where bcrypt's cost would be paid per call. The
    -- UNIQUE constraint is also the index that read uses.
    key_hash     TEXT NOT NULL UNIQUE,
    -- Host-defined permission strings as a JSON array, denormalised
    -- into the row rather than given a join table. Authentication reads
    -- this on every request and must stay one indexed lookup; a scope
    -- is also opaque to the engine, so there is nothing to query it by.
    scopes       JSONB,
    -- NULL means a key that never expires, which is the default.
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Updated coarsely, not per request (see auth.AuthenticateAPIKey):
    -- this answers 'is anything still using this key?', and a write per
    -- request would make one row the hottest lock in the schema.
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

-- Per-user listing of live keys, the only read here that is not by
-- key_hash. Partial, matching idx_sessions_user_active: revoked keys
-- are never listed.
CREATE INDEX idx_api_keys_user_active ON api_keys(user_id) WHERE revoked_at IS NULL;
