ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_fingerprint_state_key;
-- statement
ALTER TABLE alerts ADD COLUMN active_fingerprint VARCHAR(255);
-- statement
ALTER TABLE alerts ADD COLUMN acknowledged_by VARCHAR(128);
-- statement
ALTER TABLE alerts ADD COLUMN acknowledged_at BIGINT;
-- statement
ALTER TABLE alerts ADD COLUMN resolved_by VARCHAR(128);
-- statement
ALTER TABLE alerts ADD COLUMN resolved_at BIGINT;
-- statement
ALTER TABLE alerts ADD COLUMN closed_by VARCHAR(128);
-- statement
ALTER TABLE alerts ADD COLUMN closed_at BIGINT;
-- statement
UPDATE alerts SET active_fingerprint=fingerprint WHERE state IN ('open','acknowledged');
-- statement
CREATE UNIQUE INDEX uq_alert_active_fingerprint ON alerts(active_fingerprint);
-- statement
CREATE TABLE IF NOT EXISTS webhook_deliveries (id CHAR(36) PRIMARY KEY, alert_id CHAR(36) NOT NULL REFERENCES alerts(id), event_type VARCHAR(64) NOT NULL, payload TEXT NOT NULL, state VARCHAR(16) NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at BIGINT NOT NULL, lease_until BIGINT, last_error TEXT NOT NULL DEFAULT '', created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, delivered_at BIGINT);
-- statement
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_claim ON webhook_deliveries(state,next_attempt_at,lease_until);
