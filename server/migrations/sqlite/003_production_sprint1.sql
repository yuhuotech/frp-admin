CREATE TABLE IF NOT EXISTS secrets (id CHAR(36) PRIMARY KEY, name VARCHAR(128) NOT NULL UNIQUE, ciphertext BLOB NOT NULL, nonce BLOB NOT NULL, key_version VARCHAR(32) NOT NULL, created_by CHAR(36) NOT NULL REFERENCES users(id), updated_by CHAR(36) NOT NULL REFERENCES users(id), created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL);
-- statement
ALTER TABLE config_revisions ADD COLUMN mode VARCHAR(16) NOT NULL DEFAULT 'raw';
-- statement
ALTER TABLE config_revisions ADD COLUMN sensitive_fields TEXT NOT NULL DEFAULT '[]';
-- statement
ALTER TABLE audit_logs ADD COLUMN outcome VARCHAR(16) NOT NULL DEFAULT 'success';
-- statement
CREATE INDEX IF NOT EXISTS idx_audit_filter ON audit_logs(created_at,actor,action);
