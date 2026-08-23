package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/frp-admin/frp-admin/agent/internal/discovery"
	"github.com/frp-admin/frp-admin/agent/internal/securitycheck"
	"github.com/frp-admin/frp-admin/agent/internal/service"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

type Collector interface {
	Collect(context.Context) (*agentv1.Inventory, error)
}

type Local struct {
	binaryPath, configPath, serviceName, discoveryState string
	candidates                                          []discovery.Candidate
	services                                            service.Manager
	security                                            securitycheck.Collector
	configReader                                        func(context.Context, string) ([]byte, error)
}

func New(binaryPath, configPath, serviceName, discoveryState string, candidates []discovery.Candidate, services service.Manager, security ...securitycheck.Collector) *Local {
	var checks securitycheck.Collector
	if len(security) > 0 {
		checks = security[0]
	}
	return &Local{binaryPath: binaryPath, configPath: configPath, serviceName: serviceName, discoveryState: discoveryState, candidates: candidates, services: services, security: checks}
}

func (l *Local) WithConfigReader(reader func(context.Context, string) ([]byte, error)) *Local {
	l.configReader = reader
	return l
}

func (l *Local) Collect(ctx context.Context) (*agentv1.Inventory, error) {
	host, _ := os.Hostname()
	status, err := l.services.Status(ctx)
	if err != nil {
		status = &agentv1.ServiceStatus{State: agentv1.ServiceState_SERVICE_STATE_UNKNOWN, SubState: "status_unavailable"}
	}
	result := &agentv1.Inventory{Hostname: host, OperatingSystem: runtime.GOOS,
		Architecture: runtime.GOARCH, KernelVersion: kernel(ctx), FrpBinaryPath: l.binaryPath,
		FrpVersion: version(ctx, l.binaryPath), ServiceName: l.serviceName, Service: status,
		CollectedAtUnixMs: time.Now().UnixMilli(), FrpConfigPath: l.configPath, FrpConfigDiscoveryState: l.discoveryState}
	for _, candidate := range l.candidates {
		result.FrpConfigCandidates = append(result.FrpConfigCandidates, &agentv1.ConfigCandidate{BinaryPath: candidate.BinaryPath, ConfigPath: candidate.ConfigPath, ServiceName: candidate.ServiceName, Source: candidate.Source, Error: candidate.Error})
	}
	var content []byte
	var configErr error
	if l.configReader != nil {
		content, configErr = l.configReader(ctx, l.configPath)
	} else {
		content, configErr = os.ReadFile(l.configPath)
	}
	if configErr == nil && len(content) > 0 && len(content) <= 1<<20 {
		sum := sha256.Sum256(content)
		result.FrpConfigSha256 = hex.EncodeToString(sum[:])
		result.FrpConfigContent = content
		if result.FrpConfigDiscoveryState == "" {
			result.FrpConfigDiscoveryState = "resolved"
		}
	} else if result.FrpConfigDiscoveryState == "" {
		result.FrpConfigDiscoveryState = "unavailable"
	}
	if l.security != nil {
		scan := l.security.Collect(ctx)
		result.DeploymentRisks = scan.Findings
		result.DeploymentRiskCompletedKinds = scan.CompletedKinds
		result.DeploymentRiskScanComplete = scan.Complete
		result.DeploymentRiskScanErrorCode = scan.ErrorCode
	}
	return result, nil
}

func kernel(ctx context.Context) string {
	b, err := exec.CommandContext(ctx, "uname", "-r").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func version(ctx context.Context, binary string) string {
	if binary == "" {
		return ""
	}
	b, err := exec.CommandContext(ctx, binary, "--version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
