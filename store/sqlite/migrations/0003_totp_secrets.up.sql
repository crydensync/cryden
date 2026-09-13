-- 0003_totp_secrets.up.sql (SQLite)
--
-- Equivalent of Postgres migration 0003.

CREATE TABLE totp_secrets (
    user_id          TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Encrypted (AES-256-GCM), never plaintext, never hashed — the
    -- engine must recover the original secret to validate a code
    -- against it, so hashing (as used for passwords) doesn't apply.
    encrypted_secret TEXT NOT NULL,
    -- NULL until the user proves possession with one valid code.
    -- An unconfirmed secret must never gate a login.
    confirmed_at     TEXT,
    created_at       TEXT NOT NULL
);
