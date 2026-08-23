package migrations

import (
	"strings"
	"testing"
)

func TestConfigurationMigrationParity(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		data, e := files.ReadFile(dialect + "/002_configuration.sql")
		if e != nil {
			t.Fatal(e)
		}
		sql := strings.ToLower(string(data))
		for _, required := range []string{"config_revisions", "encrypted_content", "nonce", "sha256", "payload", "config_revision_id", "expected_revision_id"} {
			if !strings.Contains(sql, required) {
				t.Errorf("%s migration missing %s", dialect, required)
			}
		}
		if strings.Contains(sql, "raw_content") || strings.Contains(sql, " plaintext") {
			t.Errorf("%s migration contains plaintext config column", dialect)
		}
	}
}

func TestProductionSprint1MigrationParity(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		data, err := files.ReadFile(dialect + "/003_production_sprint1.sql")
		if err != nil {
			t.Fatal(err)
		}
		sql := strings.ToLower(string(data))
		for _, required := range []string{
			"create table if not exists secrets",
			"ciphertext",
			"nonce",
			"key_version",
			"add column mode",
			"add column sensitive_fields",
			"add column outcome",
		} {
			if !strings.Contains(sql, required) {
				t.Errorf("%s migration missing %s", dialect, required)
			}
		}
		for _, forbidden := range []string{" plaintext", " raw_value", " secret_value", " value text", " value blob", " value bytea"} {
			if strings.Contains(sql, forbidden) {
				t.Errorf("%s migration contains forbidden secret value column %q", dialect, forbidden)
			}
		}
	}
}

func TestMySQLMigrationsUseSingleStatementChunks(t *testing.T) {
	entries, err := files.ReadDir("mysql")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		data, err := files.ReadFile("mysql/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, chunk := range strings.Split(string(data), "-- statement") {
			if strings.Count(chunk, ";") > 1 {
				t.Errorf("mysql/%s contains multiple SQL statements in one execution chunk", entry.Name())
			}
		}
	}
}

func TestProductionSprint2MigrationParity(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		data, err := files.ReadFile(dialect + "/004_production_sprint2.sql")
		if err != nil {
			t.Fatal(err)
		}
		sql := strings.ToLower(string(data))
		for _, required := range []string{"expires_at", "cancel_requested_at", "idx_tasks_expiry", "create table if not exists alerts", "fingerprint"} {
			if !strings.Contains(sql, required) {
				t.Errorf("%s migration missing %s", dialect, required)
			}
		}
	}
}

func TestAlertOutboxMigrationParity(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		data, err := files.ReadFile(dialect + "/005_alert_outbox.sql")
		if err != nil {
			t.Fatal(err)
		}
		sql := strings.ToLower(string(data))
		for _, required := range []string{"active_fingerprint", "uq_alert_active_fingerprint", "acknowledged_by", "resolved_at", "closed_at", "create table if not exists webhook_deliveries", "next_attempt_at", "lease_until", "last_error", "idx_webhook_delivery_claim"} {
			if !strings.Contains(sql, required) {
				t.Errorf("%s migration missing %s", dialect, required)
			}
		}
	}
}

func TestUpgradeAndRuntimeMigrationParity(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		upgrade, err := files.ReadFile(dialect + "/006_upgrade_plans.sql")
		if err != nil {
			t.Fatal(err)
		}
		upgradeSQL := strings.ToLower(string(upgrade))
		for _, required := range []string{"upgrade_plans", "artifact_ciphertext", "artifact_nonce", "artifact_key_version", "upgrade_plan_id", "idx_tasks_upgrade_plan"} {
			if !strings.Contains(upgradeSQL, required) {
				t.Errorf("%s upgrade migration missing %s", dialect, required)
			}
		}
		for _, forbidden := range []string{"artifact_url", "presigned", "query_token"} {
			if strings.Contains(upgradeSQL, forbidden) {
				t.Errorf("%s upgrade migration contains plaintext artifact field %s", dialect, forbidden)
			}
		}
		runtime, err := files.ReadFile(dialect + "/007_runtime_snapshots.sql")
		if err != nil {
			t.Fatal(err)
		}
		runtimeSQL := strings.ToLower(string(runtime))
		for _, required := range []string{"runtime_snapshots", "runtime_proxies", "runtime_clients", "bytes_in", "bytes_out", "collected_at", "idx_runtime_proxies_filter"} {
			if !strings.Contains(runtimeSQL, required) {
				t.Errorf("%s runtime migration missing %s", dialect, required)
			}
		}
	}
}

func TestDeploymentRiskMigrationParity(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		data, err := files.ReadFile(dialect + "/008_deployment_risks.sql")
		if err != nil {
			t.Fatal(err)
		}
		sql := strings.ToLower(string(data))
		for _, required := range []string{"deployment_risks", "deployment_risk_scans", "rule_version", "confidence", "evidence", "resource_fingerprint", "pending_confirmation_at", "repair_task_id", "missed_scans", "status", "error_code", "unique"} {
			if !strings.Contains(sql, required) {
				t.Errorf("%s deployment risk migration missing %s", dialect, required)
			}
		}
	}
}

func TestRiskScanIdentityMigrationParity(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		data, err := files.ReadFile(dialect + "/010_risk_scan_identity.sql")
		if err != nil {
			t.Fatal(err)
		}
		sql := strings.ToLower(string(data))
		for _, required := range []string{"unique", "deployment_risk_scans", "task_id"} {
			if !strings.Contains(sql, required) {
				t.Errorf("%s risk scan identity migration missing %s", dialect, required)
			}
		}
	}
}
