-- 0006_login_attempts.up.sql (SQLite)
--
-- Equivalent of Postgres migration 0006.

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
