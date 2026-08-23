package inventory

import (
	"context"
	"errors"
	"testing"

	"github.com/frp-admin/frp-admin/agent/internal/securitycheck"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

type unavailableService struct{}

func (unavailableService) Status(context.Context) (*agentv1.ServiceStatus, error) {
	return nil, errors.New("service manager unavailable")
}
func (unavailableService) Act(context.Context, agentv1.ServiceAction) (*agentv1.ServiceStatus, error) {
	return nil, errors.New("service manager unavailable")
}

type fixedSecurity struct{ result securitycheck.Result }

func (f fixedSecurity) Collect(context.Context) securitycheck.Result { return f.result }

func TestSecurityScanContinuesWhenServiceStatusIsUnavailable(t *testing.T) {
	kind := agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_CONFIG_TOKEN_PERMISSIONS
	collector := New("", "frpc", unavailableService{}, fixedSecurity{result: securitycheck.Result{
		Findings: []*agentv1.DeploymentRisk{{Kind: kind}}, CompletedKinds: []agentv1.DeploymentRiskKind{kind}, Complete: true,
	}})
	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.GetService().GetState() != agentv1.ServiceState_SERVICE_STATE_UNKNOWN || len(result.GetDeploymentRisks()) != 1 || len(result.GetDeploymentRiskCompletedKinds()) != 1 {
		t.Fatalf("inventory=%+v", result)
	}
}
