-- 0001_initial_schema.up.sql (SQLite)
--
-- Equivalent of Postgres migration 0001. Split to mirror Postgres
-- file-for-file rather than the earlier single consolidated file,
-- so both backends grow the same way from here on.
--
-- Three type conventions run through every file in this directory,
-- and the Go code in this package depends on all three:
--
--   * Timestamps are TEXT, holding RFC 3339 in UTC with a fixed nine
--     fractional digits ("2026-09-05T12:34:56.123456789Z"). TEXT is
--     inert: every driver hands back the bytes that were written,
--     and the fixed width keeps lexicographic order equal to
--     chronological order.
--
--   * Identifiers are TEXT PRIMARY KEY NOT NULL. The NOT NULL is not
--     redundant: in SQLite a PRIMARY KEY column that is not INTEGER
--     still accepts NULL unless it says otherwise.
--
--   * Booleans-by-absence stay as they are in Postgres — a NULL
--     revoked_at/used_at/confirmed_at means "not yet", never a flag
--     column.
--
-- Foreign keys are declared below but SQLite only enforces them when
-- the connection sets PRAGMA foreign_keys = ON. Set it in the DSN —
-- see this package's doc comment. UserStore.Delete does not rely on
-- it either way.

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
