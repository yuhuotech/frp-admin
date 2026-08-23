ALTER TABLE tasks ADD COLUMN expires_at BIGINT;

ALTER TABLE tasks ADD COLUMN cancel_requested_at BIGINT;

CREATE INDEX IF NOT EXISTS idx_tasks_expiry ON tasks(state, expires_at);

CREATE TABLE IF NOT EXISTS alerts (id CHAR(36) PRIMARY KEY, kind VARCHAR(64) NOT NULL, severity VARCHAR(16) NOT NULL, state VARCHAR(16) NOT NULL, resource VARCHAR(255) NOT NULL, fingerprint VARCHAR(255) NOT NULL, message TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, UNIQUE(fingerprint, state));

CREATE INDEX IF NOT EXISTS idx_alerts_state_created ON alerts(state, created_at, id);
