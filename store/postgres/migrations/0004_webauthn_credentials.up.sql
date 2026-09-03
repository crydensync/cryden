-- 0004_webauthn_credentials.up.sql

CREATE TABLE webauthn_credentials (
    id              UUID PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Denormalized out of credential_data purely so it's indexable —
    -- matching a credential during login, excluding it during
    -- re-registration, without deserializing every row first.
    credential_id   BYTEA NOT NULL,
    -- JSON-marshaled webauthn.Credential from the go-webauthn library,
    -- stored as a blob rather than decomposed into columns — that
    -- struct gains fields as the library evolves, and a blob avoids
    -- this schema drifting out of sync with it.
    credential_data JSONB NOT NULL,
    -- User-supplied label ("MacBook Touch ID"), purely presentational.
    nickname        TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,
    UNIQUE (credential_id)
);

CREATE INDEX idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
