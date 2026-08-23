package securitycheck

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

func TestCollectFindsProductionDeploymentRisks(t *testing.T) {
	config := []byte(`[webServer]
addr = "0.0.0.0"
port = 7500
[auth]
token = "do-not-report-this"
`)
	collector := New("server", filepath.Join(t.TempDir(), "frps.toml"), "frps.service")
	collector.readConfig = func(string) ([]byte, os.FileMode, error) { return config, 0644, nil }
	collector.readLog = func(context.Context, string, string) ([]byte, error) {
		return []byte("proxy name [prod-db] is already in use"), nil
	}
	result := collector.Collect(context.Background())
	got := result.Findings
	if !result.Complete || result.ErrorCode != "" {
		t.Fatalf("scan status=%+v", result)
	}
	if len(result.CompletedKinds) != 3 {
		t.Fatalf("completed kinds=%v", result.CompletedKinds)
	}
	want := []agentv1.DeploymentRiskKind{
		agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_ADMIN_API_NON_LOOPBACK,
		agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_CONFIG_TOKEN_PERMISSIONS,
		agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_PROXY_NAME_CONFLICT,
	}
	if len(got) != len(want) {
		t.Fatalf("risks=%v", got)
	}
	for i := range want {
		if got[i].GetKind() != want[i] {
			t.Fatalf("risk[%d]=%v want %v", i, got[i].GetKind(), want[i])
		}
		if len(got[i].GetResourceFingerprint()) != 64 {
			t.Fatalf("risk[%d] fingerprint=%q", i, got[i].GetResourceFingerprint())
		}
	}
}

func TestCollectTreatsLoopbackAndMode0600AsSafe(t *testing.T) {
	collector := New("server", "/tmp/frps.yaml", "frps.service")
	collector.readConfig = func(string) ([]byte, os.FileMode, error) {
		return []byte("webServer:\n  addr: 127.0.0.1\n  port: 7500\nauth:\n  token: secret\n"), 0600, nil
	}
	collector.readLog = func(context.Context, string, string) ([]byte, error) { return []byte("proxy ssh started"), nil }
	if got := collector.Collect(context.Background()); !got.Complete || len(got.Findings) != 0 {
		t.Fatalf("unexpected risks: %v", got)
	}
}

func TestCollectUsesNonLoopbackDefaultWhenAdminAPIIsEnabled(t *testing.T) {
	collector := New("server", "/tmp/frps.json", "frps.service")
	collector.readConfig = func(string) ([]byte, os.FileMode, error) {
		return []byte(`{"webServer":{"port":7500}}`), 0600, nil
	}
	collector.readLog = func(context.Context, string, string) ([]byte, error) { return nil, nil }
	got := collector.Collect(context.Background()).Findings
	if len(got) != 1 || got[0].GetKind() != agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_ADMIN_API_NON_LOOPBACK {
		t.Fatalf("risks=%v", got)
	}
}

func TestCollectDoesNotFlagDisabledAdminAPI(t *testing.T) {
	collector := New("server", "/tmp/frps.toml", "frps.service")
	collector.readConfig = func(string) ([]byte, os.FileMode, error) {
		return []byte("[webServer]\naddr = '0.0.0.0'\nport = 0\n"), 0600, nil
	}
	collector.readLog = func(context.Context, string, string) ([]byte, error) { return nil, nil }
	if got := collector.Collect(context.Background()); !got.Complete || len(got.Findings) != 0 {
		t.Fatalf("unexpected risks: %v", got)
	}
}

func TestClientDoesNotFlagAdminAddress(t *testing.T) {
	collector := New("client", "/tmp/frpc.toml", "frpc.service")
	collector.readConfig = func(string) ([]byte, os.FileMode, error) {
		return []byte("[webServer]\naddr='0.0.0.0'\nport=7500\n"), 0600, nil
	}
	collector.readLog = func(context.Context, string, string) ([]byte, error) { return nil, nil }
	if got := collector.Collect(context.Background()); !got.Complete || len(got.Findings) != 0 || len(got.CompletedKinds) != 2 {
		t.Fatalf("unexpected risks: %v", got)
	}
}

func TestCollectReportsUnknownInsteadOfResolvingOnReadFailures(t *testing.T) {
	collector := New("server", "/tmp/frps.toml", "frps.service")
	collector.readConfig = func(string) ([]byte, os.FileMode, error) {
		return nil, 0, os.ErrPermission
	}
	result := collector.Collect(context.Background())
	if result.Complete || result.ErrorCode != "CONFIG_READ_FAILED" || len(result.Findings) != 0 {
		t.Fatalf("read failure result=%+v", result)
	}

	collector.readConfig = func(string) ([]byte, os.FileMode, error) {
		return []byte("[auth]\ntoken='redacted'\n"), 0644, nil
	}
	collector.readLog = func(context.Context, string, string) ([]byte, error) {
		return nil, os.ErrPermission
	}
	result = collector.Collect(context.Background())
	if result.Complete || result.ErrorCode != "LOG_READ_FAILED" || len(result.Findings) != 1 {
		t.Fatalf("log failure result=%+v", result)
	}
	if len(result.CompletedKinds) != 2 {
		t.Fatalf("config rules should remain complete: %v", result.CompletedKinds)
	}
	if result.Findings[0].GetEvidence() != "config_mode=0644" {
		t.Fatalf("unsafe evidence=%q", result.Findings[0].GetEvidence())
	}
}
