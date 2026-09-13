-- 0002_api_keys.up.sql (SQLite)
--
-- The first real 0002 here, as 0001's header said the next feature to
-- need a table would be. It is the equivalent of Postgres migration
-- 0007, and follows the same three type conventions 0001 documents at
-- length: TEXT timestamps at fixed width, TEXT identifiers declared
-- NOT NULL, and NULL as 'not yet' rather than a flag column.

CREATE TABLE api_keys (
    id           TEXT PRIMARY KEY NOT NULL,
    -- ON DELETE CASCADE, not SET NULL: a key with no owner would
    -- authenticate as nobody, so it must die with the account. Only
    -- enforced when the connection sets PRAGMA foreign_keys = ON, which
    -- is why UserStore.Delete deletes these rows by hand as well.
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL DEFAULT '',
    prefix       TEXT NOT NULL DEFAULT '',
    -- SHA-256 of the whole raw key, not bcrypt: crypto/rand output
    -- rather than a human-chosen secret, and read on every machine
    -- request. The UNIQUE constraint is also the index that read uses.
    key_hash     TEXT NOT NULL UNIQUE,
    -- A JSON array of host-defined permission strings. TEXT holding
    -- JSON, which is what this backend maps Postgres JSONB onto —
    -- passed as a string so SQLite's json_* functions can read it.
    scopes       TEXT,
    expires_at   TEXT,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at   TEXT
);

-- Per-user listing of live keys, the only read here that is not by
-- key_hash. Partial, matching idx_sessions_user_active.
CREATE INDEX idx_api_keys_user_active ON api_keys(user_id) WHERE revoked_at IS NULL;
