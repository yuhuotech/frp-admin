package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSecretFileOverridesAndConflicts(t *testing.T) {
	for _, key := range []string{"FRP_ADMIN_DATABASE_DSN", "FRP_ADMIN_DATABASE_DSN_FILE", "FRP_ADMIN_BOOTSTRAP_TOKEN", "FRP_ADMIN_BOOTSTRAP_TOKEN_FILE", "FRP_ADMIN_ALERT_WEBHOOK_URL", "FRP_ADMIN_ALERT_WEBHOOK_SECRET_FILE"} {
		t.Setenv(key, "")
	}
	dir := t.TempDir()
	dsnFile, tokenFile := filepath.Join(dir, "dsn"), filepath.Join(dir, "token")
	if e := os.WriteFile(dsnFile, []byte(":memory:\n"), 0o600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(tokenFile, []byte("bootstrap-from-file\n"), 0o600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("FRP_ADMIN_DATABASE_DSN_FILE", dsnFile)
	t.Setenv("FRP_ADMIN_BOOTSTRAP_TOKEN_FILE", tokenFile)
	cfg, e := Load("")
	if e != nil {
		t.Fatal(e)
	}
	if cfg.Database.DSN != ":memory:" || cfg.Bootstrap.Token != "bootstrap-from-file" {
		t.Fatalf("file overrides not loaded")
	}
	t.Setenv("FRP_ADMIN_DATABASE_DSN", "direct")
	if _, e = Load(""); e == nil {
		t.Fatal("direct DSN and DSN file accepted together")
	}
}

func TestTaskTimeoutBoundariesAndEnvironmentOverrides(t *testing.T) {
	keys := []string{"FRP_ADMIN_TASK_TIMEOUT_INSPECT", "FRP_ADMIN_TASK_TIMEOUT_SERVICE", "FRP_ADMIN_TASK_TIMEOUT_CONFIG", "FRP_ADMIN_TASK_TIMEOUT_UPGRADE"}
	for _, key := range keys {
		t.Run(key+" minimum", func(t *testing.T) {
			for _, item := range keys {
				t.Setenv(item, "")
			}
			t.Setenv(key, "999ms")
			if _, err := Load(""); err == nil {
				t.Fatal("sub-second task timeout accepted")
			}
			t.Setenv(key, "1s")
			cfg, err := Load("")
			if err != nil {
				t.Fatal(err)
			}
			values := map[string]time.Duration{"FRP_ADMIN_TASK_TIMEOUT_INSPECT": cfg.Tasks.Timeouts.Inspect, "FRP_ADMIN_TASK_TIMEOUT_SERVICE": cfg.Tasks.Timeouts.Service, "FRP_ADMIN_TASK_TIMEOUT_CONFIG": cfg.Tasks.Timeouts.Config, "FRP_ADMIN_TASK_TIMEOUT_UPGRADE": cfg.Tasks.Timeouts.Upgrade}
			if values[key] != time.Second {
				t.Fatalf("override=%s", values[key])
			}
			t.Setenv(key, "24h1s")
			if _, err = Load(""); err == nil {
				t.Fatal("task timeout above 24h accepted")
			}
		})
	}
}

func TestAlertWebhookRequiresSecretFile(t *testing.T) {
	for _, key := range []string{"FRP_ADMIN_ALERT_WEBHOOK_URL", "FRP_ADMIN_ALERT_WEBHOOK_SECRET_FILE", "FRP_ADMIN_ALERT_WEBHOOK_ALLOWED_HOSTS", "FRP_ADMIN_ALERT_WEBHOOK_ALLOW_PRIVATE_ADDRESSES"} {
		t.Setenv(key, "")
	}
	t.Setenv("FRP_ADMIN_ALERT_WEBHOOK_URL", "https://alerts.example.test/hook")
	if _, err := Load(""); err == nil {
		t.Fatal("webhook URL accepted without signing secret")
	}
	path := filepath.Join(t.TempDir(), "webhook-secret")
	if err := os.WriteFile(path, []byte("signing-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FRP_ADMIN_ALERT_WEBHOOK_SECRET_FILE", path)
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Alerting.WebhookSecret != "signing-secret" {
		t.Fatal("webhook secret file not loaded")
	}
	t.Setenv("FRP_ADMIN_ALERT_WEBHOOK_ALLOW_PRIVATE_ADDRESSES", "true")
	if _, err = Load(""); err == nil {
		t.Fatal("private webhook accepted without exact host allowlist")
	}
	t.Setenv("FRP_ADMIN_ALERT_WEBHOOK_ALLOWED_HOSTS", "alerts.example.test")
	cfg, err = Load("")
	if err != nil || !cfg.Alerting.AllowPrivateAddresses || len(cfg.Alerting.AllowedHosts) != 1 {
		t.Fatalf("private webhook policy not loaded: cfg=%+v err=%v", cfg.Alerting, err)
	}
}

func TestMetricsListenerDefaultsDisabledAndSupportsEnv(t *testing.T) {
	t.Setenv("FRP_ADMIN_METRICS_ADDRESS", "")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Metrics.Address != "" {
		t.Fatalf("metrics unexpectedly enabled at %s", cfg.Metrics.Address)
	}
	t.Setenv("FRP_ADMIN_METRICS_ADDRESS", "127.0.0.1:19090")
	cfg, err = Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Metrics.Address != "127.0.0.1:19090" {
		t.Fatalf("metrics address=%s", cfg.Metrics.Address)
	}
}
