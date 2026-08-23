CREATE UNIQUE INDEX IF NOT EXISTS uq_deployment_risk_scans_task ON deployment_risk_scans(task_id) WHERE task_id IS NOT NULL;
