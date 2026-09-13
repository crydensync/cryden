-- 0002_oauth_identities.up.sql (SQLite)
--
-- Equivalent of Postgres migration 0002.

CREATE TABLE oauth_identities (
    id          TEXT PRIMARY KEY NOT NULL,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider    TEXT NOT NULL,
    external_id TEXT NOT NULL,
    email       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    -- Backstops GetByProviderID and is the real guard against ever
    -- double-linking the same external account.
    UNIQUE (provider, external_id)
);

CREATE INDEX idx_oauth_identities_user_id ON oauth_identities(user_id);
