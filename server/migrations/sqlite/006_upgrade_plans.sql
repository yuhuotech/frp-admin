CREATE TABLE IF NOT EXISTS upgrade_plans (id CHAR(36) PRIMARY KEY, node_id CHAR(36) NOT NULL REFERENCES nodes(id), version VARCHAR(64) NOT NULL, artifact_ciphertext BLOB NOT NULL, artifact_nonce BLOB NOT NULL, artifact_key_version VARCHAR(32) NOT NULL, sha256 CHAR(64) NOT NULL, state VARCHAR(32) NOT NULL, task_id CHAR(36) NOT NULL UNIQUE, created_by CHAR(36) NOT NULL REFERENCES users(id), created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL);
-- statement
CREATE INDEX IF NOT EXISTS idx_upgrade_plans_history ON upgrade_plans(created_at,id);
-- statement
CREATE INDEX IF NOT EXISTS idx_upgrade_plans_node ON upgrade_plans(node_id,created_at);
-- statement
ALTER TABLE tasks ADD COLUMN upgrade_plan_id CHAR(36) REFERENCES upgrade_plans(id);
-- statement
CREATE INDEX IF NOT EXISTS idx_tasks_upgrade_plan ON tasks(upgrade_plan_id);
