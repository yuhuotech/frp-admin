package roothelper

import agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"

const (
	OperationProbe               = "probe"
	OperationProbeService        = "probe_service"
	OperationServiceStart        = "service_start"
	OperationServiceStop         = "service_stop"
	OperationServiceRestart      = "service_restart"
	OperationScan                = "scan_deployment_risks"
	OperationInspect             = "inspect_config_resource"
	OperationRestrictPermissions = "restrict_config_permissions"
	OperationApplyAdminLoopback  = "apply_admin_loopback"
)

type Request struct {
	Operation          string `json:"operation"`
	ExpectedCurrentSHA string `json:"expectedCurrentSHA"`
	CandidateRevision  string `json:"candidateRevision,omitempty"`
	CandidateSHA       string `json:"candidateSHA,omitempty"`
	CandidateContent   []byte `json:"candidateContent,omitempty"`
	CandidateStrategy  string `json:"candidateStrategy,omitempty"`
}

type Response struct {
	ErrorCode         agentv1.ErrorCode            `json:"errorCode"`
	Diagnostic        string                       `json:"diagnostic,omitempty"`
	BackupCreated     bool                         `json:"backupCreated"`
	BackupID          string                       `json:"backupID,omitempty"`
	Changed           bool                         `json:"changed"`
	RollbackAttempted bool                         `json:"rollbackAttempted"`
	RollbackSucceeded bool                         `json:"rollbackSucceeded"`
	Findings          []*agentv1.DeploymentRisk    `json:"findings,omitempty"`
	CompletedKinds    []agentv1.DeploymentRiskKind `json:"completedKinds,omitempty"`
	ScanErrorCode     string                       `json:"scanErrorCode,omitempty"`
	ResourceSHA       string                       `json:"resourceSHA,omitempty"`
	ServiceStatus     *agentv1.ServiceStatus       `json:"serviceStatus,omitempty"`
}
