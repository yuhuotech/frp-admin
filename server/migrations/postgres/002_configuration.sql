CREATE TABLE IF NOT EXISTS config_revisions (id CHAR(36) PRIMARY KEY, node_id CHAR(36) NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, version BIGINT NOT NULL, encrypted_content BYTEA NOT NULL, nonce BYTEA NOT NULL, sha256 CHAR(64) NOT NULL, strategy VARCHAR(32) NOT NULL, created_by CHAR(36) NOT NULL REFERENCES users(id), created_at BIGINT NOT NULL, UNIQUE(node_id,version));
-- statement
CREATE INDEX IF NOT EXISTS idx_config_revisions_node_created ON config_revisions(node_id,created_at,id);
-- statement
ALTER TABLE tasks ADD COLUMN payload TEXT NOT NULL DEFAULT '{}';
-- statement
ALTER TABLE tasks ADD COLUMN config_revision_id CHAR(36);
-- statement
ALTER TABLE tasks ADD COLUMN expected_revision_id CHAR(36);
