CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, applied_at BIGINT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- statement
INSERT IGNORE INTO schema_migrations(version, applied_at) VALUES (1, UNIX_TIMESTAMP(UTC_TIMESTAMP(6))*1000000);
-- statement
CREATE TABLE IF NOT EXISTS users (id CHAR(36) PRIMARY KEY, username VARCHAR(128) NOT NULL UNIQUE, password_hash LONGTEXT NOT NULL, status VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- statement
CREATE TABLE IF NOT EXISTS user_roles (user_id CHAR(36) PRIMARY KEY, role VARCHAR(32) NOT NULL, CONSTRAINT fk_roles_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- statement
CREATE TABLE IF NOT EXISTS sessions (id CHAR(36) PRIMARY KEY, user_id CHAR(36) NOT NULL, token_hash CHAR(64) NOT NULL UNIQUE, csrf_hash CHAR(64) NOT NULL, expires_at BIGINT NOT NULL, revoked_at BIGINT NULL, created_at BIGINT NOT NULL, INDEX idx_sessions_user(user_id), CONSTRAINT fk_sessions_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- statement
CREATE TABLE IF NOT EXISTS enrollment_tokens (id CHAR(36) PRIMARY KEY, token_hash CHAR(64) NOT NULL UNIQUE, role VARCHAR(16) NOT NULL, expires_at BIGINT NOT NULL, used_at BIGINT NULL, created_by CHAR(36) NOT NULL, created_at BIGINT NOT NULL, CONSTRAINT fk_enroll_user FOREIGN KEY(created_by) REFERENCES users(id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- statement
CREATE TABLE IF NOT EXISTS nodes (id CHAR(36) PRIMARY KEY, name VARCHAR(255) NOT NULL, role VARCHAR(16) NOT NULL, labels LONGTEXT NOT NULL, management_mode VARCHAR(16) NOT NULL, desired_revision_id CHAR(36) NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- statement
CREATE TABLE IF NOT EXISTS node_observations (node_id CHAR(36) PRIMARY KEY, online BOOLEAN NOT NULL, agent_version VARCHAR(64) NOT NULL, frp_version VARCHAR(64) NOT NULL, service_state VARCHAR(32) NOT NULL, observed_hash VARCHAR(128) NOT NULL, observed_revision_id CHAR(36) NULL, last_heartbeat BIGINT NOT NULL, CONSTRAINT fk_obs_node FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- statement
CREATE TABLE IF NOT EXISTS tasks (id CHAR(36) PRIMARY KEY, type VARCHAR(64) NOT NULL, state VARCHAR(32) NOT NULL, node_id CHAR(36) NULL, idempotency_key VARCHAR(255) NOT NULL, requested_by CHAR(36) NOT NULL, error_code VARCHAR(64) NOT NULL, error_message LONGTEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, UNIQUE KEY uq_task_idem(node_id,idempotency_key), INDEX idx_tasks_created(created_at,id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- statement
CREATE TABLE IF NOT EXISTS task_steps (id CHAR(36) PRIMARY KEY, task_id CHAR(36) NOT NULL, name VARCHAR(128) NOT NULL, state VARCHAR(32) NOT NULL, attempt INT NOT NULL, error_code VARCHAR(64) NOT NULL, output LONGTEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, CONSTRAINT fk_steps_task FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- statement
CREATE TABLE IF NOT EXISTS audit_logs (id CHAR(36) PRIMARY KEY, actor VARCHAR(128) NOT NULL, action VARCHAR(128) NOT NULL, resource VARCHAR(255) NOT NULL, request_id VARCHAR(128) NOT NULL, created_at BIGINT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
