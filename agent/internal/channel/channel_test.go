package channel

import (
	"slices"
	"testing"
	"time"

	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

func TestHelloCapabilitiesIncludeRiskScanAndOnlyAvailableRepairs(t *testing.T) {
	base := helloCapabilities(nil)
	if len(base) != 0 {
		t.Fatalf("base=%v", base)
	}
	for _, capability := range []string{"config.apply", "config.rollback", "frp.upgrade"} {
		if slices.Contains(base, capability) {
			t.Fatalf("privileged capability %q must require an explicit preflight", capability)
		}
	}
	withRepair := helloCapabilities([]string{"risk.scan", "risk.repair.config_permissions", "risk.repair.config_permissions"})
	if !slices.Contains(withRepair, "risk.repair.config_permissions") {
		t.Fatalf("capabilities=%v", withRepair)
	}
	count := 0
	for _, capability := range withRepair {
		if capability == "risk.repair.config_permissions" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate repair capability: %v", withRepair)
	}
}

func TestHeartbeatIncludesWelcomeSession(t *testing.T) {
	now := time.UnixMilli(1234)
	message := heartbeatMessage("session-42", 7, now)
	heartbeat := message.GetHeartbeat()
	if heartbeat.GetSessionId() != "session-42" || heartbeat.GetSequence() != 7 || heartbeat.GetSentAtUnixMs() != 1234 {
		t.Fatalf("heartbeat=%v", heartbeat)
	}
}

func TestWelcomeDefinesHeartbeatSessionAndInterval(t *testing.T) {
	sessionID, interval, err := welcomeSettings(&agentv1.Welcome{SessionId: "session-42", HeartbeatIntervalSeconds: 20}, 15*time.Second)
	if err != nil || sessionID != "session-42" || interval != 20*time.Second {
		t.Fatalf("session=%q interval=%s err=%v", sessionID, interval, err)
	}
	if _, _, err := welcomeSettings(&agentv1.Welcome{}, 15*time.Second); err == nil {
		t.Fatal("expected empty session id to be rejected")
	}
}
