ALTER TABLE alerts DROP INDEX uq_alert_fingerprint_state;
-- statement
ALTER TABLE alerts ADD COLUMN active_fingerprint VARCHAR(255) NULL;
-- statement
ALTER TABLE alerts ADD COLUMN acknowledged_by VARCHAR(128) NULL;
-- statement
ALTER TABLE alerts ADD COLUMN acknowledged_at BIGINT NULL;
-- statement
ALTER TABLE alerts ADD COLUMN resolved_by VARCHAR(128) NULL;
-- statement
ALTER TABLE alerts ADD COLUMN resolved_at BIGINT NULL;
-- statement
ALTER TABLE alerts ADD COLUMN closed_by VARCHAR(128) NULL;
-- statement
ALTER TABLE alerts ADD COLUMN closed_at BIGINT NULL;
-- statement
UPDATE alerts SET active_fingerprint=fingerprint WHERE state IN ('open','acknowledged') AND active_fingerprint IS NULL;
-- statement
CREATE UNIQUE INDEX uq_alert_active_fingerprint ON alerts(active_fingerprint);
-- statement
CREATE TABLE IF NOT EXISTS webhook_deliveries (id CHAR(36) PRIMARY KEY, alert_id CHAR(36) NOT NULL, event_type VARCHAR(64) NOT NULL, payload LONGTEXT NOT NULL, state VARCHAR(16) NOT NULL, attempts INT NOT NULL DEFAULT 0, next_attempt_at BIGINT NOT NULL, lease_until BIGINT NULL, last_error LONGTEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, delivered_at BIGINT NULL, INDEX idx_webhook_delivery_claim(state,next_attempt_at,lease_until), CONSTRAINT fk_webhook_alert FOREIGN KEY(alert_id) REFERENCES alerts(id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
