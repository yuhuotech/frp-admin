CREATE TABLE IF NOT EXISTS config_revisions (id CHAR(36) PRIMARY KEY, node_id CHAR(36) NOT NULL, version BIGINT NOT NULL, encrypted_content LONGBLOB NOT NULL, nonce BLOB NOT NULL, sha256 CHAR(64) NOT NULL, strategy VARCHAR(32) NOT NULL, created_by CHAR(36) NOT NULL, created_at BIGINT NOT NULL, UNIQUE KEY uq_config_version(node_id,version), INDEX idx_config_revisions_node_created(node_id,created_at,id), CONSTRAINT fk_config_node FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE, CONSTRAINT fk_config_user FOREIGN KEY(created_by) REFERENCES users(id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- statement
ALTER TABLE tasks ADD COLUMN payload LONGTEXT NOT NULL DEFAULT ('{}');
-- statement
ALTER TABLE tasks ADD COLUMN config_revision_id CHAR(36) NULL;
-- statement
ALTER TABLE tasks ADD COLUMN expected_revision_id CHAR(36) NULL;
