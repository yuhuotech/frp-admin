CREATE TABLE IF NOT EXISTS secrets (id CHAR(36) PRIMARY KEY, name VARCHAR(128) NOT NULL UNIQUE, ciphertext LONGBLOB NOT NULL, nonce BLOB NOT NULL, key_version VARCHAR(32) NOT NULL, created_by CHAR(36) NOT NULL, updated_by CHAR(36) NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, CONSTRAINT fk_secret_created_user FOREIGN KEY(created_by) REFERENCES users(id), CONSTRAINT fk_secret_updated_user FOREIGN KEY(updated_by) REFERENCES users(id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- statement
ALTER TABLE config_revisions ADD COLUMN mode VARCHAR(16) NOT NULL DEFAULT 'raw';
-- statement
ALTER TABLE config_revisions ADD COLUMN sensitive_fields LONGTEXT NOT NULL DEFAULT ('[]');
-- statement
ALTER TABLE audit_logs ADD COLUMN outcome VARCHAR(16) NOT NULL DEFAULT 'success';
-- statement
CREATE INDEX idx_audit_filter ON audit_logs(created_at,actor,action);
