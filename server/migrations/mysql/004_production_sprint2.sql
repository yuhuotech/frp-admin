ALTER TABLE tasks ADD COLUMN expires_at BIGINT NULL;
-- statement
ALTER TABLE tasks ADD COLUMN cancel_requested_at BIGINT NULL;
-- statement
CREATE INDEX idx_tasks_expiry ON tasks(state, expires_at);
-- statement
CREATE TABLE IF NOT EXISTS alerts (id CHAR(36) PRIMARY KEY, kind VARCHAR(64) NOT NULL, severity VARCHAR(16) NOT NULL, state VARCHAR(16) NOT NULL, resource VARCHAR(255) NOT NULL, fingerprint VARCHAR(255) NOT NULL, message LONGTEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, UNIQUE KEY uq_alert_fingerprint_state(fingerprint, state), INDEX idx_alerts_state_created(state, created_at, id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
