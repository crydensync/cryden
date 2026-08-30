-- 0003_totp_secrets.up.sql

CREATE TABLE totp_secrets (
    user_id          UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- Encrypted (AES-256-GCM), never plaintext, never hashed — the
    -- engine must recover the original secret to validate a code
    -- against it, so hashing (as used for passwords) doesn't apply.
    encrypted_secret TEXT NOT NULL,
    -- NULL until the user proves possession with one valid code.
    -- An unconfirmed secret must never gate a login.
    confirmed_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
