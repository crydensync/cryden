-- 0004_webauthn_credentials.up.sql (SQLite)
--
-- Equivalent of Postgres migration 0004.

CREATE TABLE webauthn_credentials (
    id              TEXT PRIMARY KEY NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Raw bytes, so BLOB rather than Postgres's BYTEA. Denormalized
    -- out of credential_data purely so it's indexable — matching a
    -- credential during login, excluding it during re-registration,
    -- without deserializing every row first.
    credential_id   BLOB NOT NULL,
    -- JSON-marshaled webauthn.Credential from the go-webauthn library,
    -- stored as a blob rather than decomposed into columns — that
    -- struct gains fields as the library evolves, and a blob avoids
    -- this schema drifting out of sync with it.
    credential_data TEXT NOT NULL,
    -- User-supplied label ("MacBook Touch ID"), purely presentational.
    nickname        TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    last_used_at    TEXT,
    UNIQUE (credential_id)
);

CREATE INDEX idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
