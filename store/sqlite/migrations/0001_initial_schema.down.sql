-- 0001_initial_schema.down.sql (SQLite)
--
-- Dropped children-first. SQLite tolerates dropping a parent before
-- its children even with foreign keys on, but relying on that would
-- be a needless bet.

DROP TABLE IF EXISTS verification_tokens;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
