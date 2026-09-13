-- 0001_initial_schema.down.sql (SQLite)
--
-- Dropped children-first. SQLite tolerates dropping a parent before its
-- children even with foreign keys on (the dropped table's rows are
-- deleted, and the FK violation is only reported at the end of the
-- statement), but relying on that would be a needless bet.

DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS recovery_codes;
DROP TABLE IF EXISTS webauthn_credentials;
DROP TABLE IF EXISTS totp_secrets;
DROP TABLE IF EXISTS oauth_identities;
DROP TABLE IF EXISTS verification_tokens;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
