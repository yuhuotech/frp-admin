CREATE TABLE alerts_v5 (id CHAR(36) PRIMARY KEY, kind VARCHAR(64) NOT NULL, severity VARCHAR(16) NOT NULL, state VARCHAR(16) NOT NULL, resource VARCHAR(255) NOT NULL, fingerprint VARCHAR(255) NOT NULL, active_fingerprint VARCHAR(255), message TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, acknowledged_by VARCHAR(128), acknowledged_at BIGINT, resolved_by VARCHAR(128), resolved_at BIGINT, closed_by VARCHAR(128), closed_at BIGINT);
-- statement
INSERT INTO alerts_v5(id,kind,severity,state,resource,fingerprint,active_fingerprint,message,created_at,updated_at) SELECT id,kind,severity,state,resource,fingerprint,CASE WHEN state IN ('open','acknowledged') THEN fingerprint ELSE NULL END,message,created_at,updated_at FROM alerts;
-- statement
DROP TABLE alerts;
-- statement
ALTER TABLE alerts_v5 RENAME TO alerts;
-- statement
CREATE UNIQUE INDEX uq_alert_active_fingerprint ON alerts(active_fingerprint);
-- statement
CREATE INDEX idx_alerts_state_created ON alerts(state,created_at,id);
-- statement
CREATE TABLE IF NOT EXISTS webhook_deliveries (id CHAR(36) PRIMARY KEY, alert_id CHAR(36) NOT NULL REFERENCES alerts(id), event_type VARCHAR(64) NOT NULL, payload TEXT NOT NULL, state VARCHAR(16) NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at BIGINT NOT NULL, lease_until BIGINT, last_error TEXT NOT NULL DEFAULT '', created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, delivered_at BIGINT);
-- statement
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_claim ON webhook_deliveries(state,next_attempt_at,lease_until);
