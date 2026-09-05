-- 0001_initial_schema.up.sql (SQLite)
--
-- One file, not the six store/postgres/migrations grew over time.
-- That history is real for Postgres — each feature added its table as
-- it shipped — but no SQLite database has ever existed at any of those
-- intermediate points, so numbering this 0001..0006 would be inventing
-- a past. This is the consolidated equivalent of Postgres migrations
-- 0001 through 0006; the next feature to need a table adds 0002 here
-- for real.
--
-- Three type conventions run through the whole file, and the Go code in
-- this package depends on all three:
--
--   * Timestamps are TEXT, holding RFC 3339 in UTC with a fixed nine
--     fractional digits ("2026-09-05T12:34:56.123456789Z"). SQLite has
--     no date type, and the two things that could stand in for one are
--     both worse: an INTEGER epoch stops being readable the moment an
--     operator opens the file by hand, and a column declared DATETIME
--     makes some drivers (notably mattn/go-sqlite3) convert it to a
--     Go time.Time behind this package's back, so the same schema would
--     read back differently depending on which driver the host chose.
--     TEXT is inert: every driver hands back the bytes that were
--     written. The fixed width is what keeps lexicographic order equal
--     to chronological order, which is what lets created_at >= ? and
--     ORDER BY created_at DESC work as plain string comparisons.
--
--   * Identifiers are TEXT PRIMARY KEY NOT NULL. The NOT NULL is not
--     redundant: in SQLite a PRIMARY KEY column that is not INTEGER
--     still accepts NULL unless it says otherwise, a documented quirk
--     kept for backward compatibility.
--
--   * Booleans-by-absence stay as they are in Postgres — a NULL
--     revoked_at/used_at/confirmed_at means "not yet", never a flag
--     column.
--
-- Foreign keys are declared below but SQLite only enforces them when
-- the connection sets PRAGMA foreign_keys = ON, which is off by
-- default and cannot be set from inside this file (the pragma is a
-- no-op within a transaction, and Migrate runs one). Set it in the
-- DSN — see this package's doc comment. UserStore.Delete does not rely
-- on it either way.

CREATE TABLE users (
    id              TEXT PRIMARY KEY NOT NULL,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE sessions (
    id          TEXT PRIMARY KEY NOT NULL,
    family_id   TEXT NOT NULL,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    ip          TEXT,
    user_agent  TEXT,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT
);

-- Rotation-family lookups and per-user active session listing, the
-- same two access patterns the Postgres schema indexes. GetByTokenHash
-- needs no index of its own: the UNIQUE above already is one.
CREATE INDEX idx_sessions_family_id ON sessions(family_id);
CREATE INDEX idx_sessions_user_active ON sessions(user_id) WHERE revoked_at IS NULL;

CREATE TABLE audit_events (
    id         TEXT PRIMARY KEY NOT NULL,
    type       TEXT NOT NULL,
    -- Nullable: a login_failed event for a nonexistent email has no
    -- user to attribute to. Never invent a user_id in that case.
    user_id    TEXT REFERENCES users(id) ON DELETE SET NULL,
    ip         TEXT,
    -- Postgres stores this JSONB; here it is JSON in a TEXT column,
    -- which is what SQLite's own JSON functions operate on anyway —
    -- there is no separate JSON storage type to choose.
    metadata   TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_audit_events_user_id ON audit_events(user_id, created_at DESC);
-- SearchByType reads system-wide by type, which in Postgres was a
-- sequential scan the admin tooling could afford. SQLite is usually a
-- much smaller dataset on much weaker hardware, and this index costs
-- one B-tree — cheap enough to just have.
CREATE INDEX idx_audit_events_type ON audit_events(type, created_at DESC);

CREATE TABLE verification_tokens (
    id          TEXT PRIMARY KEY NOT NULL,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose     TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    -- Only populated for purpose = 'email_change'; the address the
    -- user is trying to change TO, not their current one.
    new_email   TEXT,
    expires_at  TEXT NOT NULL,
    used_at     TEXT,
    created_at  TEXT NOT NULL
);

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

CREATE TABLE recovery_codes (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- SHA-256, not bcrypt — a recovery code is a high-entropy random
    -- value generated by the engine, not a user-chosen secret, so
    -- there's no weak-guessing risk a slow hash would defend against.
    -- Globally unique on its own, so it's the primary key directly
    -- rather than introducing a separate id column just to have one.
    code_hash  TEXT PRIMARY KEY NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_recovery_codes_user_id ON recovery_codes(user_id);

CREATE TABLE login_attempts (
    id         TEXT PRIMARY KEY NOT NULL,
    -- Nullable, and ON DELETE SET NULL rather than CASCADE: a deleted
    -- account's attempt rows still carry real evidence about the IP
    -- that targeted it, which is exactly what per-IP velocity needs.
    -- Matching audit_events, not sessions/recovery_codes.
    user_id    TEXT REFERENCES users(id) ON DELETE SET NULL,
    ip         TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    outcome    TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    created_at TEXT NOT NULL
);

-- Every read of this table is an aggregate over a time window, never a
-- full scan for a human to page through — that difference from
-- audit_events is the entire reason this table exists separately, so
-- the indexes are what justify it. Partial indexes, as in Postgres:
-- SQLite has supported them since 3.8.0.

-- Per-user failure velocity (CountFailuresForUser).
CREATE INDEX idx_login_attempts_user_failures
    ON login_attempts(user_id, created_at DESC)
    WHERE outcome = 'failure';

-- Per-IP failure velocity (CountFailuresForIP) and breadth
-- (CountTargetsForIP), counted across every account one IP targeted,
-- including unknown-email attempts where user_id IS NULL.
CREATE INDEX idx_login_attempts_ip_failures
    ON login_attempts(ip, created_at DESC)
    WHERE outcome = 'failure';

-- Known-IP/known-device baseline (ListRecentSuccesses).
CREATE INDEX idx_login_attempts_user_successes
    ON login_attempts(user_id, created_at DESC)
    WHERE outcome = 'success';
