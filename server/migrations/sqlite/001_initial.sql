CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at BIGINT NOT NULL);
-- statement
INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (1, unixepoch('subsec') * 1000000);
-- statement
CREATE TABLE IF NOT EXISTS users (id CHAR(36) PRIMARY KEY, username VARCHAR(128) NOT NULL UNIQUE, password_hash TEXT NOT NULL, status VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL);
-- statement
CREATE TABLE IF NOT EXISTS user_roles (user_id CHAR(36) PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, role VARCHAR(32) NOT NULL);
-- statement
CREATE TABLE IF NOT EXISTS sessions (id CHAR(36) PRIMARY KEY, user_id CHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE, token_hash CHAR(64) NOT NULL UNIQUE, csrf_hash CHAR(64) NOT NULL, expires_at BIGINT NOT NULL, revoked_at BIGINT, created_at BIGINT NOT NULL);
-- statement
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
-- statement
CREATE TABLE IF NOT EXISTS enrollment_tokens (id CHAR(36) PRIMARY KEY, token_hash CHAR(64) NOT NULL UNIQUE, role VARCHAR(16) NOT NULL, expires_at BIGINT NOT NULL, used_at BIGINT, created_by CHAR(36) NOT NULL REFERENCES users(id), created_at BIGINT NOT NULL);
-- statement
CREATE TABLE IF NOT EXISTS nodes (id CHAR(36) PRIMARY KEY, name VARCHAR(255) NOT NULL, role VARCHAR(16) NOT NULL, labels TEXT NOT NULL, management_mode VARCHAR(16) NOT NULL, desired_revision_id CHAR(36), created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL);
-- statement
CREATE TABLE IF NOT EXISTS node_observations (node_id CHAR(36) PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE, online INTEGER NOT NULL, agent_version VARCHAR(64) NOT NULL, frp_version VARCHAR(64) NOT NULL, service_state VARCHAR(32) NOT NULL, observed_hash VARCHAR(128) NOT NULL, observed_revision_id CHAR(36), last_heartbeat BIGINT NOT NULL);
-- statement
CREATE TABLE IF NOT EXISTS tasks (id CHAR(36) PRIMARY KEY, type VARCHAR(64) NOT NULL, state VARCHAR(32) NOT NULL, node_id CHAR(36), idempotency_key VARCHAR(255) NOT NULL, requested_by CHAR(36) NOT NULL, error_code VARCHAR(64) NOT NULL, error_message TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, UNIQUE(node_id, idempotency_key));
-- statement
CREATE INDEX IF NOT EXISTS idx_tasks_created ON tasks(created_at, id);
-- statement
CREATE TABLE IF NOT EXISTS task_steps (id CHAR(36) PRIMARY KEY, task_id CHAR(36) NOT NULL REFERENCES tasks(id) ON DELETE CASCADE, name VARCHAR(128) NOT NULL, state VARCHAR(32) NOT NULL, attempt INTEGER NOT NULL, error_code VARCHAR(64) NOT NULL, output TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL);
-- statement
CREATE TABLE IF NOT EXISTS audit_logs (id CHAR(36) PRIMARY KEY, actor VARCHAR(128) NOT NULL, action VARCHAR(128) NOT NULL, resource VARCHAR(255) NOT NULL, request_id VARCHAR(128) NOT NULL, created_at BIGINT NOT NULL);
