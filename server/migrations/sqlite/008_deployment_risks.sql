CREATE TABLE IF NOT EXISTS deployment_risks (id CHAR(36) PRIMARY KEY, node_id CHAR(36) NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, kind VARCHAR(64) NOT NULL, severity VARCHAR(16) NOT NULL, state VARCHAR(32) NOT NULL, evidence TEXT NOT NULL, confidence VARCHAR(16) NOT NULL, rule_version VARCHAR(32) NOT NULL, resource_fingerprint CHAR(64) NOT NULL, repair_task_id CHAR(36), missed_scans INTEGER NOT NULL DEFAULT 0, first_seen_at BIGINT NOT NULL, last_seen_at BIGINT NOT NULL, pending_confirmation_at BIGINT, resolved_at BIGINT, updated_at BIGINT NOT NULL, UNIQUE(node_id, kind));
-- statement
CREATE INDEX IF NOT EXISTS idx_deployment_risks_filter ON deployment_risks(state,node_id,kind,updated_at);
-- statement
CREATE TABLE IF NOT EXISTS deployment_risk_scans (id CHAR(36) PRIMARY KEY, node_id CHAR(36) NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, task_id CHAR(36), status VARCHAR(16) NOT NULL, error_code VARCHAR(64) NOT NULL, finding_count INTEGER NOT NULL, scanned_at BIGINT NOT NULL);
-- statement
CREATE INDEX IF NOT EXISTS idx_deployment_risk_scans_node ON deployment_risk_scans(node_id,scanned_at);
