CREATE TABLE IF NOT EXISTS upgrade_plans (id CHAR(36) PRIMARY KEY, node_id CHAR(36) NOT NULL, version VARCHAR(64) NOT NULL, artifact_ciphertext LONGBLOB NOT NULL, artifact_nonce BLOB NOT NULL, artifact_key_version VARCHAR(32) NOT NULL, sha256 CHAR(64) NOT NULL, state VARCHAR(32) NOT NULL, task_id CHAR(36) NOT NULL, created_by CHAR(36) NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, UNIQUE KEY uq_upgrade_task(task_id), INDEX idx_upgrade_plans_history(created_at,id), INDEX idx_upgrade_plans_node(node_id,created_at), CONSTRAINT fk_upgrade_node FOREIGN KEY(node_id) REFERENCES nodes(id), CONSTRAINT fk_upgrade_user FOREIGN KEY(created_by) REFERENCES users(id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- statement
ALTER TABLE tasks ADD COLUMN upgrade_plan_id CHAR(36) NULL;
-- statement
CREATE INDEX idx_tasks_upgrade_plan ON tasks(upgrade_plan_id);
-- statement
ALTER TABLE tasks ADD CONSTRAINT fk_task_upgrade_plan FOREIGN KEY(upgrade_plan_id) REFERENCES upgrade_plans(id);
