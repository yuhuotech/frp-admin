package agentgateway

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/events"
	"github.com/frp-admin/frp-admin/server/internal/metrics"
	"github.com/frp-admin/frp-admin/server/internal/pki"
	"github.com/frp-admin/frp-admin/server/internal/store"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type Service struct {
	agentv1.UnimplementedAgentControlServiceServer
	store        store.Store
	pki          *pki.Manager
	events       *events.Bus
	logger       *slog.Logger
	now          func() time.Time
	mu           sync.Mutex
	sessions     map[string]*agentSession
	materializer ConfigMaterializer
	importer     ConfigImporter
	upgrades     UpgradeMaterializer
	alerter      AlertSink
}

type AlertSink interface {
	Trigger(context.Context, string, string, string, string)
}

type agentSession struct {
	id           string
	stream       agentv1.AgentControlService_ConnectServer
	capabilities map[string]struct{}
	sendMu       sync.Mutex
}

func NewService(s store.Store, p *pki.Manager, b *events.Bus, l *slog.Logger, materializers ...ConfigMaterializer) *Service {
	v := &Service{store: s, pki: p, events: b, logger: l, now: time.Now, sessions: map[string]*agentSession{}}
	if len(materializers) > 0 {
		v.materializer = materializers[0]
	}
	return v
}
func (s *Service) SetAlertSink(v AlertSink)                     { s.alerter = v }
func (s *Service) SetUpgradeMaterializer(v UpgradeMaterializer) { s.upgrades = v }
func (s *Service) SetConfigImporter(v ConfigImporter)           { s.importer = v }

func (s *Service) Enroll(ctx context.Context, req *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	role := protoRole(req.GetRole())
	if role == "" {
		return nil, status.Error(codes.InvalidArgument, "role must be client or server")
	}
	if req.GetEnrollmentToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "enrollment token is required")
	}
	name := strings.TrimSpace(req.GetHostname())
	if name == "" || len(name) > 255 {
		return nil, status.Error(codes.InvalidArgument, "hostname is required and must not exceed 255 characters")
	}
	nodeID := uuid.Must(uuid.NewV7()).String()
	cert, expires, err := s.pki.SignClient(req.GetPublicKeyPem(), nodeID, 30*24*time.Hour)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	sum := sha256.Sum256([]byte(req.GetEnrollmentToken()))
	now := s.now().UTC()
	node := domain.Node{ID: nodeID, Name: name, Role: role, Labels: "{}", ManagementMode: "observe", CreatedAt: now, UpdatedAt: now}
	if err = s.store.ConsumeEnrollmentTokenAndCreateNode(ctx, hex.EncodeToString(sum[:]), role, node, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Error(codes.PermissionDenied, "enrollment token is invalid, expired, used, or has a different role")
		}
		return nil, status.Error(codes.Internal, "persist enrollment failed")
	}
	s.events.Publish(events.Event{ID: nodeID, Type: "node.enrolled", Data: []byte(`{}`)})
	s.logger.InfoContext(ctx, "agent enrolled", "node_id", nodeID, "role", role)
	return &agentv1.EnrollResponse{NodeId: nodeID, CertificatePem: cert, CaCertificatePem: s.pki.CAPEM(), CertificateExpiresAtUnixMs: expires.UnixMilli()}, nil
}

func (s *Service) Connect(stream agentv1.AgentControlService_ConnectServer) error {
	cert, err := verifiedClientCertificate(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.FailedPrecondition, "first frame must be Hello")
	}
	if hello.GetProtocolVersion() != 1 {
		return status.Error(codes.FailedPrecondition, "unsupported Agent protocol version")
	}
	if err = certificateMatchesNode(cert, hello.GetNodeId()); err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	node, err := s.store.NodeByID(stream.Context(), hello.GetNodeId())
	if err != nil {
		return status.Error(codes.PermissionDenied, "certificate node is not managed")
	}
	if node.Role != protoRole(hello.GetRole()) {
		return status.Error(codes.PermissionDenied, "certificate node role does not match Hello")
	}
	sessionID := uuid.Must(uuid.NewV7()).String()
	now := s.now().UTC()
	sessionCapabilities := safeCapabilities(hello.GetCapabilities())
	capabilities, _ := json.Marshal(sessionCapabilities)
	obs := domain.NodeObservation{NodeID: node.ID, Online: true, AgentVersion: truncate(hello.GetAgentVersion(), 64), FRPVersion: truncate(hello.GetFrpVersion(), 64), ServiceState: "unknown", Capabilities: string(capabilities), LastHeartbeat: now}
	if err = s.store.UpsertObservation(stream.Context(), obs); err != nil {
		return status.Error(codes.Internal, "persist Hello failed")
	}
	if err = stream.Send(&agentv1.ServerToAgent{Payload: &agentv1.ServerToAgent_Welcome{Welcome: &agentv1.Welcome{SessionId: sessionID, ServerTimeUnixMs: now.UnixMilli(), HeartbeatIntervalSeconds: 15}}}); err != nil {
		return err
	}
	s.setSession(node.ID, sessionID, stream, sessionCapabilities)
	metrics.Default.AgentConnected()
	defer metrics.Default.AgentDisconnected()
	defer s.disconnect(stream.Context(), node.ID, sessionID)
	if err = s.dispatchQueued(stream.Context(), node.ID, sessionCapabilities); err != nil {
		return err
	}
	s.events.Publish(events.Event{ID: node.ID, Type: "node.online", Data: []byte(`{}`)})
	for {
		msg, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			return nil
		}
		if recvErr != nil {
			return recvErr
		}
		if !s.currentSession(node.ID, sessionID) {
			return status.Error(codes.Aborted, "agent session was superseded")
		}
		now = s.now().UTC()
		switch {
		case msg.GetHeartbeat() != nil:
			if subtle.ConstantTimeCompare([]byte(msg.GetHeartbeat().GetSessionId()), []byte(sessionID)) != 1 {
				return status.Error(codes.PermissionDenied, "heartbeat session ID mismatch")
			}
			obs.Online = true
			obs.LastHeartbeat = now
		case msg.GetInventory() != nil:
			inv := msg.GetInventory()
			obs.Online = true
			if s.importer != nil && len(inv.GetFrpConfigContent()) > 0 && validConfigDiscoveryHash(inv.GetFrpConfigContent(), inv.GetFrpConfigSha256()) {
				if _, importErr := s.importer.ImportDiscovered(stream.Context(), node.ID, inv.GetFrpConfigContent()); importErr != nil {
					s.logger.WarnContext(stream.Context(), "discovered FRP config was not imported", "node_id", node.ID, "error", importErr)
				}
			}
			obs.LastHeartbeat = now
			if inv.GetFrpVersion() != "" {
				obs.FRPVersion = truncate(inv.GetFrpVersion(), 64)
			}
			obs.OperatingSystem, obs.Architecture = truncate(inv.GetOperatingSystem(), 32), truncate(inv.GetArchitecture(), 32)
			obs.FrpBinaryPath, obs.FrpConfigPath = truncate(inv.GetFrpBinaryPath(), 512), truncate(inv.GetFrpConfigPath(), 512)
			obs.ConfigDiscoveryState, obs.ConfigSHA256 = truncate(inv.GetFrpConfigDiscoveryState(), 32), truncate(inv.GetFrpConfigSha256(), 128)
			obs.ServiceState = serviceState(inv.GetService().GetState())
			s.reconcileDeploymentRisks(stream.Context(), node.ID, "", inv)
		case msg.GetCertificateRotationRequest() != nil:
			request := msg.GetCertificateRotationRequest()
			if !validRotationRequestID(request.GetRequestId()) {
				return status.Error(codes.InvalidArgument, "certificate rotation request ID is invalid")
			}
			if request.GetCurrentSerial() != cert.SerialNumber.String() {
				return status.Error(codes.PermissionDenied, "certificate rotation serial does not match the authenticated certificate")
			}
			if request.GetCertificateExpiresAtUnixMs() != cert.NotAfter.UnixMilli() {
				return status.Error(codes.InvalidArgument, "certificate rotation expiry does not match the authenticated certificate")
			}
			if cert.NotAfter.After(now.Add(8 * 24 * time.Hour)) {
				return status.Error(codes.FailedPrecondition, "certificate is not within its rotation window")
			}
			certificatePEM, expires, signErr := s.pki.SignClientCSR(request.GetCsrPem(), node.ID, node.Role, 30*24*time.Hour)
			if signErr != nil {
				return status.Error(codes.InvalidArgument, "certificate rotation CSR is invalid")
			}
			response := &agentv1.ServerToAgent{Payload: &agentv1.ServerToAgent_RotateCertificate{RotateCertificate: &agentv1.RotateCertificate{
				RequestId: request.GetRequestId(), CertificatePem: certificatePEM, CaCertificatePem: s.pki.CAPEM(), CertificateExpiresAtUnixMs: expires.UnixMilli(),
			}}}
			if sendErr := s.sendSession(node.ID, sessionID, response); sendErr != nil {
				return sendErr
			}
			s.logger.InfoContext(stream.Context(), "agent certificate rotated", "node_id", node.ID, "request_id", request.GetRequestId(), "expires_at", expires)
			continue
		case msg.GetCommandAck() != nil:
			ack := msg.GetCommandAck()
			if _, err = s.authorizeTask(stream.Context(), ack.GetCommandId(), node.ID); err != nil {
				return err
			}
			if err = s.store.UpdateTask(stream.Context(), ack.GetCommandId(), "running", "", "", "running", "", now); err != nil && !errors.Is(err, store.ErrNotFound) {
				if errors.Is(err, store.ErrConflict) {
					continue
				}
				return status.Error(codes.Internal, "persist command acknowledgement failed")
			}
			s.publishTask(ack.GetCommandId())
			continue
		case msg.GetCommandProgress() != nil:
			progress := msg.GetCommandProgress()
			if _, err = s.authorizeTask(stream.Context(), progress.GetCommandId(), node.ID); err != nil {
				return err
			}
			if err = s.store.UpdateTask(stream.Context(), progress.GetCommandId(), "running", "", "", "running", truncate(progress.GetStage(), 512), now); err != nil && !errors.Is(err, store.ErrNotFound) {
				if errors.Is(err, store.ErrConflict) {
					continue
				}
				return status.Error(codes.Internal, "persist command progress failed")
			}
			s.publishTask(progress.GetCommandId())
			continue
		case msg.GetCommandResult() != nil:
			result := msg.GetCommandResult()
			taskRecord, authErr := s.authorizeTask(stream.Context(), result.GetCommandId(), node.ID)
			if authErr != nil {
				return authErr
			}
			taskState := commandStatus(result.GetStatus())
			errorCode := commandError(result.GetErrorCode())
			diagnostic := safeCommandDiagnostic(taskRecord.Type, errorCode)
			var runtimeSnapshot *domain.RuntimeSnapshot
			stepOutput := diagnostic
			var inspectInventory *agentv1.Inventory
			if runtimeResult := result.GetRuntime(); runtimeResult != nil {
				if taskRecord.Type != "collect_runtime" {
					return status.Error(codes.InvalidArgument, "runtime result does not belong to a runtime collection task")
				}
				converted, convertErr := runtimeFromProto(runtimeResult.GetSnapshot(), node.ID, now)
				if convertErr != nil {
					taskState, errorCode, diagnostic = "failed", "INVALID_RESPONSE", convertErr.Error()
				} else {
					runtimeSnapshot = &converted
				}
			}
			if repair := result.GetRepairDeploymentRisk(); repair != nil {
				if taskRecord.Type != "risk_repair" {
					return status.Error(codes.InvalidArgument, "risk repair result does not belong to a repair task")
				}
			}
			if inspect := result.GetInspect(); inspect != nil {
				inspectInventory = inspect.GetInventory()
			}
			if taskRecord.Type == "risk_repair" {
				taskState, errorCode, diagnostic, stepOutput = normalizeRepairResult(taskState, errorCode, diagnostic, result.GetRepairDeploymentRisk())
			}
			configChangingRepair := taskRecord.Type == "risk_repair" && taskRecord.ConfigRevisionID != nil
			var appliedSHA string
			if configChangingRepair && taskState == "succeeded" {
				repair := result.GetRepairDeploymentRisk()
				var payload struct{ CandidateSHA256 string }
				_ = json.Unmarshal([]byte(taskRecord.Payload), &payload)
				if repair == nil || repair.GetAppliedRevision() != *taskRecord.ConfigRevisionID || !validResultSHA256(payload.CandidateSHA256) || repair.GetAppliedSha256() != payload.CandidateSHA256 {
					taskState, errorCode, diagnostic = "failed", "INVALID_RESPONSE", "risk repair applied revision proof is invalid"
				} else {
					appliedSHA = payload.CandidateSHA256
				}
			}
			completion := domain.TaskCompletionOutcome{FinalState: taskState, Transitioned: true}
			if taskRecord.Type == "risk_scan" || (taskRecord.Type == "inspect" && inspectInventory != nil) {
				var findings []domain.DeploymentRiskObservation
				var completedKinds []string
				scanStatus, scanError := "fail", "INVALID_RESPONSE"
				if inspectInventory == nil {
					taskState, errorCode, diagnostic, stepOutput = "failed", "INVALID_RESPONSE", "risk scan inventory is missing", "risk scan inventory is missing"
				} else {
					findings, completedKinds, scanStatus, scanError = deploymentRiskScanData(inspectInventory)
				}
				completion, err = s.store.CompleteRiskScanTask(stream.Context(), taskRecord, taskState, errorCode, diagnostic, stepOutput, scanStatus, scanError, findings, completedKinds, now)
				if err == nil && completion.Transitioned {
					s.triggerDeploymentRiskAlerts(stream.Context(), node.ID, findings)
				}
			} else if taskRecord.Type == "config_apply" || taskRecord.Type == "config_rollback" || taskRecord.Type == "risk_repair" {
				requestedState := taskState
				completion, err = s.store.CompleteConfigTask(stream.Context(), taskRecord, taskState, errorCode, diagnostic, stepOutput, appliedSHA, now)
				if requestedState == "succeeded" && completion.FinalState == "failed" && completion.Transitioned {
					errorCode, diagnostic = "PRECONDITION_FAILED", "node revision changed before task completion"
				}
			} else {
				if stepOutput == "" {
					stepOutput = diagnostic
				}
				completion, err = s.store.CompleteTaskResult(stream.Context(), taskRecord, taskState, errorCode, diagnostic, stepOutput, now)
			}
			if errors.Is(err, store.ErrConflict) {
				continue
			}
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return status.Error(codes.Internal, "persist command result failed")
			}
			taskState = completion.FinalState
			if repair := result.GetRepairDeploymentRisk(); repair != nil && repair.GetInventory() != nil {
				s.reconcileDeploymentRisks(stream.Context(), node.ID, result.GetCommandId(), repair.GetInventory())
			}
			if completion.AppliedDrift && s.alerter != nil {
				s.alerter.Trigger(stream.Context(), "late_repair_applied", "critical", "task/"+taskRecord.ID, "Agent applied a risk repair after the control-plane task was terminal or its revision CAS did not advance")
			}
			if !completion.Transitioned && !completion.AppliedDrift {
				continue
			}
			if runtimeSnapshot != nil && taskState == "succeeded" {
				if err = s.store.ReplaceRuntimeSnapshot(stream.Context(), *runtimeSnapshot); err != nil {
					return status.Error(codes.Internal, "persist runtime snapshot failed")
				}
			}
			if completion.Transitioned {
				metrics.Default.TaskResult(taskState)
			}
			if completion.Transitioned && taskState == "failed" && s.alerter != nil {
				kind := "task_failed"
				if taskRecord.Type == "frp_upgrade" {
					kind = "upgrade_failed"
				}
				s.alerter.Trigger(stream.Context(), kind, "critical", "task/"+taskRecord.ID, "Agent command failed: "+errorCode)
			}
			if inspectInventory != nil {
				inv := inspectInventory
				obs.FRPVersion = inv.GetFrpVersion()
				obs.OperatingSystem, obs.Architecture = truncate(inv.GetOperatingSystem(), 32), truncate(inv.GetArchitecture(), 32)
				obs.FrpBinaryPath, obs.FrpConfigPath = truncate(inv.GetFrpBinaryPath(), 512), truncate(inv.GetFrpConfigPath(), 512)
				obs.ConfigDiscoveryState, obs.ConfigSHA256 = truncate(inv.GetFrpConfigDiscoveryState(), 32), truncate(inv.GetFrpConfigSha256(), 128)
				obs.ServiceState = serviceState(inv.GetService().GetState())
				obs.LastHeartbeat = now
				if err = s.store.UpsertObservation(stream.Context(), obs); err != nil {
					return status.Error(codes.Internal, "persist inspect inventory failed")
				}
			}
			if service := result.GetService(); service != nil && service.GetStatus() != nil {
				obs.ServiceState = serviceState(service.GetStatus().GetState())
				obs.LastHeartbeat = now
				if err = s.store.UpsertObservation(stream.Context(), obs); err != nil {
					return status.Error(codes.Internal, "persist service status failed")
				}
			}
			s.publishTask(result.GetCommandId())
			continue
		default:
			continue
		}
		if err = s.store.UpsertObservation(stream.Context(), obs); err != nil {
			return status.Error(codes.Internal, "persist agent observation failed")
		}
	}
}

func (s *Service) reconcileDeploymentRisks(ctx context.Context, nodeID, taskID string, inventory *agentv1.Inventory) bool {
	if inventory == nil {
		return false
	}
	findings, completedKinds, statusValue, errorCode := deploymentRiskScanData(inventory)
	if s.store == nil {
		return false
	}
	applied, err := s.store.ReconcileDeploymentRisksOnce(ctx, nodeID, taskID, statusValue, errorCode, findings, completedKinds, s.now().UTC())
	if err != nil {
		s.logger.WarnContext(ctx, "persist deployment risk scan failed", "node_id", nodeID, "error", err)
		return false
	}
	if applied {
		s.triggerDeploymentRiskAlerts(ctx, nodeID, findings)
	}
	return applied
}

func deploymentRiskScanData(inventory *agentv1.Inventory) ([]domain.DeploymentRiskObservation, []string, string, string) {
	risks := inventory.GetDeploymentRisks()
	seen := make(map[agentv1.DeploymentRiskKind]struct{}, len(risks))
	findings := make([]domain.DeploymentRiskObservation, 0, len(risks))
	completedKinds := make([]string, 0, len(inventory.GetDeploymentRiskCompletedKinds()))
	for _, kind := range inventory.GetDeploymentRiskCompletedKinds() {
		switch kind {
		case agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_ADMIN_API_NON_LOOPBACK:
			completedKinds = append(completedKinds, "admin_api_non_loopback")
		case agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_CONFIG_TOKEN_PERMISSIONS:
			completedKinds = append(completedKinds, "config_token_permissions")
		case agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_PROXY_NAME_CONFLICT:
			completedKinds = append(completedKinds, "proxy_name_conflict")
		}
	}
	// Backward compatibility for agents that only report the legacy complete bit.
	if inventory.GetDeploymentRiskScanComplete() && len(completedKinds) == 0 {
		completedKinds = []string{"admin_api_non_loopback", "config_token_permissions", "proxy_name_conflict"}
	}
	for _, risk := range risks {
		if risk == nil {
			continue
		}
		kind := risk.GetKind()
		if _, ok := seen[kind]; ok {
			continue
		}
		seen[kind] = struct{}{}
		var alertKind, severity, message string
		switch kind {
		case agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_ADMIN_API_NON_LOOPBACK:
			alertKind, severity, message = "admin_api_non_loopback", "critical", "frps Admin API is configured on a non-loopback address"
		case agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_CONFIG_TOKEN_PERMISSIONS:
			alertKind, severity, message = "config_token_permissions", "critical", "frp configuration contains auth.token and is accessible by group or other"
		case agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_PROXY_NAME_CONFLICT:
			alertKind, severity, message = "proxy_name_conflict", "warning", "recent frp logs report a duplicate proxy name"
		default:
			continue
		}
		findings = append(findings, domain.DeploymentRiskObservation{Kind: alertKind, Severity: severity, Evidence: message, Confidence: safeRiskConfidence(risk.GetConfidence()), RuleVersion: safeRuleVersion(risk.GetRuleVersion()), ResourceFingerprint: safeResourceFingerprint(risk.GetResourceFingerprint())})
	}
	statusValue, errorCode := "unknown", truncate(inventory.GetDeploymentRiskScanErrorCode(), 64)
	if inventory.GetDeploymentRiskScanComplete() {
		statusValue = "pass"
	} else if errorCode != "" {
		statusValue = "fail"
	}
	return findings, completedKinds, statusValue, errorCode
}

func (s *Service) triggerDeploymentRiskAlerts(ctx context.Context, nodeID string, findings []domain.DeploymentRiskObservation) {
	if s.alerter == nil {
		return
	}
	for _, finding := range findings {
		s.alerter.Trigger(ctx, finding.Kind, finding.Severity, "node/"+nodeID, finding.Evidence)
	}
}

func safeRiskConfidence(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low", "medium", "high":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "unknown"
	}
}

func safeCapabilities(values []string) []string {
	allowed := map[string]struct{}{
		"inspect": {}, "service.status": {}, "service.start": {}, "service.stop": {}, "service.restart": {},
		"config.apply": {}, "config.rollback": {}, "frp.upgrade": {}, "runtime.collect": {}, "certificate.rotate": {},
		"risk.scan": {}, "risk.repair.config_permissions": {}, "risk.repair.admin_loopback": {},
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := allowed[value]; !ok {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
func safeRuleVersion(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 32 {
		return "unknown"
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '.' && r != '-' && r != '_' {
			return "unknown"
		}
	}
	return value
}
func safeResourceFingerprint(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 64 {
		return ""
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return ""
		}
	}
	return value
}

func validResultSHA256(value string) bool { return safeResourceFingerprint(value) != "" }

func normalizeRepairResult(stateValue, errorCode, diagnostic string, repair *agentv1.RepairDeploymentRiskResult) (string, string, string, string) {
	if repair == nil {
		if stateValue == "succeeded" {
			return "failed", "INVALID_RESPONSE", "deployment risk repair result is missing", ""
		}
		return stateValue, errorCode, diagnostic, ""
	}
	if stateValue == "succeeded" && !repair.GetPrecheckPassed() {
		stateValue, errorCode, diagnostic = "failed", "PRECHECK_FAILED", "deployment risk repair precheck failed"
	}
	if repair.GetChanged() && !repair.GetBackupCreated() {
		stateValue, errorCode, diagnostic = "failed", "BACKUP_FAILED", "deployment risk repair backup requirement failed"
	}
	if stateValue == "failed" && repair.GetChanged() && (!repair.GetRollbackAttempted() || !repair.GetRollbackSucceeded()) {
		errorCode, diagnostic = "RECOVERY_FAILED", "deployment risk repair rollback failed"
	}
	summary, _ := json.Marshal(map[string]bool{"precheck_passed": repair.GetPrecheckPassed(), "backup_created": repair.GetBackupCreated(), "changed": repair.GetChanged(), "rollback_attempted": repair.GetRollbackAttempted(), "rollback_succeeded": repair.GetRollbackSucceeded()})
	return stateValue, errorCode, diagnostic, string(summary)
}

// triggerDeploymentRisks preserves the alert-only test hook while production
// inventory processing uses completeness-aware reconciliation above.
func (s *Service) triggerDeploymentRisks(ctx context.Context, nodeID string, risks []*agentv1.DeploymentRisk) {
	inventory := &agentv1.Inventory{DeploymentRisks: risks, DeploymentRiskScanComplete: true}
	if s.store == nil {
		findings, _, _, _ := deploymentRiskScanData(inventory)
		s.triggerDeploymentRiskAlerts(ctx, nodeID, findings)
		return
	}
	s.reconcileDeploymentRisks(ctx, nodeID, "", inventory)
}
func validConfigDiscoveryHash(content []byte, expected string) bool {
	h := sha256.Sum256(content)
	return len(content) <= 1<<20 && strings.EqualFold(hex.EncodeToString(h[:]), strings.TrimSpace(expected))
}
func truncate(v string, max int) string {
	r := []rune(v)
	if len(r) <= max {
		return v
	}
	return string(r[:max])
}

func (s *Service) authorizeTask(ctx context.Context, taskID, nodeID string) (domain.Task, error) {
	task, e := s.store.TaskByID(ctx, taskID)
	if e != nil || task.NodeID != nodeID {
		return domain.Task{}, status.Error(codes.PermissionDenied, "command does not belong to authenticated node")
	}
	return task, nil
}
func (s *Service) dispatchQueued(ctx context.Context, nodeID string, sessionCapabilities []string) error {
	capabilities := make(map[string]struct{}, len(sessionCapabilities))
	for _, capability := range sessionCapabilities {
		capabilities[capability] = struct{}{}
	}
	page, e := s.store.ListTasks(ctx, 200, "", "queued", nodeID)
	if e != nil {
		return status.Error(codes.Internal, "load queued tasks failed")
	}
	for _, task := range page.Items {
		if task.Type != "inspect" && task.Type != "risk_scan" && task.Type != "config_apply" && task.Type != "config_rollback" && task.Type != "service_start" && task.Type != "service_stop" && task.Type != "service_restart" && task.Type != "frp_upgrade" && task.Type != "risk_repair" {
			if task.Type != "collect_runtime" {
				continue
			}
		}
		if e = s.store.UpdateTask(ctx, task.ID, "dispatched", "", "", "dispatched", "", s.now()); e != nil {
			if errors.Is(e, store.ErrConflict) {
				continue
			}
			return status.Error(codes.Internal, "claim queued task failed")
		}
		if required := requiredTaskCapability(task.Type); required != "" {
			if _, supported := capabilities[required]; !supported {
				if e = s.store.UpdateTask(ctx, task.ID, "failed", "CAPABILITY_UNAVAILABLE", "connected Agent does not support "+required, "failed", "connected Agent does not support "+required, s.now()); e != nil {
					return status.Error(codes.Internal, "fail unsupported queued task failed")
				}
				s.publishTask(task.ID)
				continue
			}
		}
		command := Command{ID: task.ID, NodeID: nodeID, Type: task.Type}
		if task.ExpiresAt != nil {
			command.ExpiresAt = *task.ExpiresAt
		}
		if task.ConfigRevisionID != nil {
			command.Revision = *task.ConfigRevisionID
		}
		if task.Type == "config_apply" || task.Type == "config_rollback" {
			if s.materializer == nil {
				return status.Error(codes.Internal, "configuration materializer unavailable")
			}
			material, materialErr := s.materializer.Materialize(ctx, command.Revision)
			if materialErr != nil {
				return status.Error(codes.Internal, "materialize queued configuration failed")
			}
			command.Payload = material.Content
			command.SHA256 = material.SHA256
			command.Strategy = material.Strategy
		}
		if task.Type == "frp_upgrade" {
			if task.UpgradePlanID == nil {
				return status.Error(codes.Internal, "upgrade task has no plan")
			}
			if s.upgrades == nil {
				return status.Error(codes.Internal, "upgrade materializer unavailable")
			}
			material, materialErr := s.upgrades.MaterializeUpgrade(ctx, *task.UpgradePlanID)
			if materialErr != nil {
				return status.Error(codes.Internal, "materialize queued upgrade failed")
			}
			command.Version, command.ArtifactURL, command.SHA256 = material.Version, material.ArtifactURL, material.SHA256
		}
		if task.Type == "risk_repair" {
			var payload struct {
				FindingID, Kind, Action, ExpectedResourceFingerprint, CandidateSHA256 string
				MaintenanceConfirmed                                                  bool
			}
			if json.Unmarshal([]byte(task.Payload), &payload) != nil || payload.FindingID == "" {
				return status.Error(codes.Internal, "invalid queued risk repair payload")
			}
			requiredCapability := "risk.repair.config_permissions"
			if payload.Action == "bind_admin_api_loopback" {
				requiredCapability = "risk.repair.admin_loopback"
			}
			if _, supported := capabilities[requiredCapability]; !supported {
				if _, updateErr := s.store.CompleteConfigTask(ctx, task, "failed", "CAPABILITY_UNAVAILABLE", "connected Agent does not support this risk repair", "connected Agent does not support this risk repair", "", s.now()); updateErr != nil {
					return status.Error(codes.Internal, "fail unsupported queued risk repair failed")
				}
				s.publishTask(task.ID)
				continue
			}
			command.RiskFindingID, command.RiskKind, command.RiskAction, command.RiskResourceFingerprint, command.MaintenanceConfirmed = payload.FindingID, payload.Kind, payload.Action, payload.ExpectedResourceFingerprint, payload.MaintenanceConfirmed
			if task.ConfigRevisionID != nil {
				if s.materializer == nil {
					return status.Error(codes.Internal, "configuration materializer unavailable")
				}
				material, materialErr := s.materializer.Materialize(ctx, *task.ConfigRevisionID)
				if materialErr != nil {
					if _, updateErr := s.store.CompleteConfigTask(ctx, task, "failed", "PRECONDITION_FAILED", "candidate material is unavailable before dispatch", "candidate material is unavailable before dispatch", "", s.now()); updateErr != nil {
						return status.Error(codes.Internal, "fail unavailable queued risk repair failed")
					}
					metrics.Default.TaskResult("failed")
					if s.alerter != nil {
						s.alerter.Trigger(ctx, "task_failed", "critical", "task/"+task.ID, "Agent command failed: PRECONDITION_FAILED")
					}
					s.publishTask(task.ID)
					continue
				}
				if !validResultSHA256(payload.CandidateSHA256) || material.SHA256 != payload.CandidateSHA256 {
					if _, updateErr := s.store.CompleteConfigTask(ctx, task, "failed", "PRECONDITION_FAILED", "candidate material changed before dispatch", "candidate material changed before dispatch", "", s.now()); updateErr != nil {
						return status.Error(codes.Internal, "fail stale queued risk repair failed")
					}
					metrics.Default.TaskResult("failed")
					if s.alerter != nil {
						s.alerter.Trigger(ctx, "task_failed", "critical", "task/"+task.ID, "Agent command failed: PRECONDITION_FAILED")
					}
					s.publishTask(task.ID)
					continue
				}
				command.Revision, command.Payload, command.SHA256, command.Strategy = material.Revision, material.Content, material.SHA256, material.Strategy
			}
		}
		if e = s.Dispatch(ctx, command); e != nil {
			_ = s.store.UpdateTask(ctx, task.ID, "queued", "", "", "queued", "", s.now())
			return e
		}
		s.publishTask(task.ID)
	}
	return nil
}

func requiredTaskCapability(taskType string) string {
	switch taskType {
	case "inspect":
		return "inspect"
	case "risk_scan":
		return "risk.scan"
	case "collect_runtime":
		return "runtime.collect"
	case "config_apply":
		return "config.apply"
	case "config_rollback":
		return "config.rollback"
	case "service_start":
		return "service.start"
	case "service_stop":
		return "service.stop"
	case "service_restart":
		return "service.restart"
	case "frp_upgrade":
		return "frp.upgrade"
	default:
		return ""
	}
}

func (s *Service) setSession(nodeID, sessionID string, stream agentv1.AgentControlService_ConnectServer, capabilities []string) {
	capabilitySet := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		capabilitySet[capability] = struct{}{}
	}
	s.mu.Lock()
	s.sessions[nodeID] = &agentSession{id: sessionID, stream: stream, capabilities: capabilitySet}
	s.mu.Unlock()
}
func (s *Service) currentSession(nodeID, sessionID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.sessions[nodeID]
	return v != nil && v.id == sessionID
}

func (s *Service) sendSession(nodeID, sessionID string, message *agentv1.ServerToAgent) error {
	s.mu.Lock()
	session := s.sessions[nodeID]
	s.mu.Unlock()
	if session == nil || session.id != sessionID {
		return ErrOffline
	}
	session.sendMu.Lock()
	defer session.sendMu.Unlock()
	if !s.currentSession(nodeID, sessionID) {
		return ErrOffline
	}
	return session.stream.Send(message)
}
func (s *Service) disconnect(ctx context.Context, nodeID, sessionID string) {
	s.mu.Lock()
	current := s.sessions[nodeID]
	if current != nil && current.id == sessionID {
		delete(s.sessions, nodeID)
	}
	s.mu.Unlock()
	if current == nil || current.id != sessionID {
		return
	}
	offlineCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if err := s.store.SetNodeOnline(offlineCtx, nodeID, false, s.now().UTC()); err != nil {
		s.logger.WarnContext(offlineCtx, "mark agent offline failed", "node_id", nodeID, "error", err)
	}
	s.events.Publish(events.Event{ID: nodeID, Type: "node.offline", Data: []byte(`{}`)})
}

func (s *Service) Connected(nodeID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[nodeID] != nil
}
func (s *Service) Dispatch(ctx context.Context, command Command) error {
	s.mu.Lock()
	session := s.sessions[command.NodeID]
	s.mu.Unlock()
	if session == nil {
		return ErrOffline
	}
	required := requiredTaskCapability(command.Type)
	if command.Type == "risk_repair" {
		required = "risk.repair.config_permissions"
		if command.RiskAction == "bind_admin_api_loopback" {
			required = "risk.repair.admin_loopback"
		}
	}
	if required != "" {
		if _, ok := session.capabilities[required]; !ok {
			return ErrCapabilityUnavailable
		}
	}
	expires := command.ExpiresAt
	if expires.IsZero() {
		expires = s.now().Add(30 * time.Second)
	}
	proto := &agentv1.Command{CommandId: command.ID, IdempotencyKey: command.ID, IssuedAtUnixMs: s.now().UnixMilli(), ExpiresAtUnixMs: expires.UnixMilli()}
	switch command.Type {
	case "inspect", "risk_scan":
		proto.Action = &agentv1.Command_Inspect{Inspect: &agentv1.InspectCommand{}}
	case "config_apply":
		if len(command.Payload) == 0 || command.Revision == "" || command.SHA256 == "" {
			return errors.New("incomplete apply config command")
		}
		proto.Action = &agentv1.Command_ApplyConfig{ApplyConfig: &agentv1.ApplyConfigCommand{Revision: command.Revision, Sha256: command.SHA256, Content: command.Payload, Strategy: command.Strategy}}
	case "config_rollback":
		if len(command.Payload) == 0 || command.Revision == "" || command.SHA256 == "" {
			return errors.New("incomplete rollback materialization")
		}
		proto.Action = &agentv1.Command_ApplyConfig{ApplyConfig: &agentv1.ApplyConfigCommand{Revision: command.Revision, Sha256: command.SHA256, Content: command.Payload, Strategy: command.Strategy}}
	case "service_start":
		proto.Action = &agentv1.Command_Service{Service: &agentv1.ServiceCommand{Action: agentv1.ServiceAction_SERVICE_ACTION_START}}
	case "service_stop":
		proto.Action = &agentv1.Command_Service{Service: &agentv1.ServiceCommand{Action: agentv1.ServiceAction_SERVICE_ACTION_STOP}}
	case "service_restart":
		proto.Action = &agentv1.Command_Service{Service: &agentv1.ServiceCommand{Action: agentv1.ServiceAction_SERVICE_ACTION_RESTART}}
	case "frp_upgrade":
		if command.Version == "" || command.ArtifactURL == "" || len(command.SHA256) != 64 {
			return errors.New("incomplete frp upgrade command")
		}
		proto.Action = &agentv1.Command_UpgradeFrp{UpgradeFrp: &agentv1.UpgradeFrpCommand{Version: command.Version, ArtifactUrl: command.ArtifactURL, Sha256: command.SHA256}}
	case "collect_runtime":
		proto.Action = &agentv1.Command_CollectRuntime{CollectRuntime: &agentv1.CollectRuntimeCommand{DetailLevel: "full"}}
	case "risk_repair":
		kind, action := deploymentRiskKind(command.RiskKind), deploymentRiskRepairAction(command.RiskAction)
		if command.RiskFindingID == "" || len(command.RiskResourceFingerprint) != 64 || kind == agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_UNSPECIFIED || action == agentv1.DeploymentRiskRepairAction_DEPLOYMENT_RISK_REPAIR_ACTION_UNSPECIFIED {
			return errors.New("incomplete deployment risk repair command")
		}
		proto.Action = &agentv1.Command_RepairDeploymentRisk{RepairDeploymentRisk: &agentv1.RepairDeploymentRiskCommand{FindingId: command.RiskFindingID, Kind: kind, Action: action, MaintenanceConfirmed: command.MaintenanceConfirmed, ExpectedResourceFingerprint: command.RiskResourceFingerprint, CandidateRevision: command.Revision, CandidateSha256: command.SHA256, CandidateContent: command.Payload, CandidateStrategy: command.Strategy}}
	default:
		return errors.New("unsupported command type")
	}
	session.sendMu.Lock()
	defer session.sendMu.Unlock()
	if !s.currentSession(command.NodeID, session.id) {
		return ErrOffline
	}
	return session.stream.Send(&agentv1.ServerToAgent{Payload: &agentv1.ServerToAgent_Command{Command: proto}})
}

func deploymentRiskKind(kind string) agentv1.DeploymentRiskKind {
	switch kind {
	case "admin_api_non_loopback":
		return agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_ADMIN_API_NON_LOOPBACK
	case "config_token_permissions":
		return agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_CONFIG_TOKEN_PERMISSIONS
	case "proxy_name_conflict":
		return agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_PROXY_NAME_CONFLICT
	default:
		return agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_UNSPECIFIED
	}
}
func deploymentRiskRepairAction(action string) agentv1.DeploymentRiskRepairAction {
	switch action {
	case "restrict_config_permissions":
		return agentv1.DeploymentRiskRepairAction_DEPLOYMENT_RISK_REPAIR_ACTION_RESTRICT_CONFIG_PERMISSIONS
	case "bind_admin_api_loopback":
		return agentv1.DeploymentRiskRepairAction_DEPLOYMENT_RISK_REPAIR_ACTION_BIND_ADMIN_API_LOOPBACK
	default:
		return agentv1.DeploymentRiskRepairAction_DEPLOYMENT_RISK_REPAIR_ACTION_UNSPECIFIED
	}
}

func (s *Service) Cancel(ctx context.Context, nodeID, commandID, reason string) error {
	s.mu.Lock()
	session := s.sessions[nodeID]
	s.mu.Unlock()
	if session == nil {
		return ErrOffline
	}
	session.sendMu.Lock()
	defer session.sendMu.Unlock()
	if !s.currentSession(nodeID, session.id) {
		return ErrOffline
	}
	return session.stream.Send(&agentv1.ServerToAgent{Payload: &agentv1.ServerToAgent_CancelCommand{CancelCommand: &agentv1.CancelCommand{CommandId: commandID, Reason: truncate(reason, 256)}}})
}
func (s *Service) publishTask(id string) {
	s.events.Publish(events.Event{ID: id, Type: "task.updated", Data: []byte(`{}`)})
}
func commandStatus(v agentv1.CommandStatus) string {
	switch v {
	case agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED:
		return "succeeded"
	case agentv1.CommandStatus_COMMAND_STATUS_CANCELLED:
		return "cancelled"
	default:
		return "failed"
	}
}

func commandError(v agentv1.ErrorCode) string {
	if v == agentv1.ErrorCode_ERROR_CODE_UNSPECIFIED {
		return ""
	}
	return strings.TrimPrefix(v.String(), "ERROR_CODE_")
}

func safeCommandDiagnostic(taskType, errorCode string) string {
	if errorCode == "" {
		return ""
	}
	switch taskType {
	case "config_apply", "config_rollback":
		if errorCode == "VERIFY_FAILED" {
			return "candidate configuration verification failed"
		}
		return "configuration operation failed"
	case "frp_upgrade":
		if errorCode == "VERIFY_FAILED" {
			return "upgrade candidate configuration verification failed"
		}
		return "upgrade operation failed"
	default:
		return "command failed"
	}
}

func runtimeFromProto(v *agentv1.RuntimeSnapshot, nodeID string, receivedAt time.Time) (domain.RuntimeSnapshot, error) {
	if v == nil || v.GetCollectedAtUnixMs() <= 0 {
		return domain.RuntimeSnapshot{}, errors.New("runtime snapshot has no collection timestamp")
	}
	collectedAt := time.UnixMilli(v.GetCollectedAtUnixMs()).UTC()
	if collectedAt.After(receivedAt.UTC().Add(5 * time.Minute)) {
		return domain.RuntimeSnapshot{}, errors.New("runtime snapshot collection timestamp is too far in the future")
	}
	if len(v.GetProxies()) > 10000 || len(v.GetClients()) > 10000 {
		return domain.RuntimeSnapshot{}, errors.New("runtime snapshot exceeds item limit")
	}
	role := protoRole(v.GetRole())
	if role == "" {
		return domain.RuntimeSnapshot{}, errors.New("runtime snapshot has invalid role")
	}
	out := domain.RuntimeSnapshot{NodeID: nodeID, Role: role, FRPVersion: truncate(v.GetFrpVersion(), 64), CollectedAt: collectedAt, Proxies: []domain.RuntimeProxy{}, Clients: []domain.RuntimeClient{}}
	if server := v.GetServer(); server != nil {
		out.BindAddress, out.BindPort, out.ProxyCount, out.ClientCount = truncate(server.GetBindAddress(), 255), int(server.GetBindPort()), int(server.GetProxyCount()), int(server.GetClientCount())
	}
	for _, p := range v.GetProxies() {
		if p == nil || strings.TrimSpace(p.GetName()) == "" {
			return domain.RuntimeSnapshot{}, errors.New("runtime proxy has no name")
		}
		traffic := p.GetTraffic()
		item := domain.RuntimeProxy{NodeID: nodeID, Name: truncate(p.GetName(), 255), Type: truncate(p.GetType(), 32), Status: runtimeProxyStatus(p.GetStatus()), LocalAddress: truncate(p.GetLocalAddress(), 512), RemoteAddress: truncate(p.GetRemoteAddress(), 512), LastError: truncate(p.GetLastError(), 2048), CollectedAt: out.CollectedAt}
		if traffic != nil {
			item.Traffic = domain.RuntimeTraffic{BytesIn: traffic.GetBytesIn(), BytesOut: traffic.GetBytesOut(), TodayBytesIn: traffic.GetTodayBytesIn(), TodayBytesOut: traffic.GetTodayBytesOut(), CurrentConnections: traffic.GetCurrentConnections()}
		}
		out.Proxies = append(out.Proxies, item)
	}
	for _, c := range v.GetClients() {
		if c == nil || strings.TrimSpace(c.GetId()) == "" {
			return domain.RuntimeSnapshot{}, errors.New("runtime client has no id")
		}
		out.Clients = append(out.Clients, domain.RuntimeClient{ID: truncate(c.GetId(), 255), Address: truncate(c.GetAddress(), 512), ConnectedAt: time.UnixMilli(c.GetConnectedAtUnixMs()).UTC()})
	}
	return out, nil
}
func runtimeProxyStatus(v agentv1.RuntimeProxyStatus) string {
	switch v {
	case agentv1.RuntimeProxyStatus_RUNTIME_PROXY_STATUS_RUNNING:
		return "running"
	case agentv1.RuntimeProxyStatus_RUNTIME_PROXY_STATUS_OFFLINE:
		return "offline"
	case agentv1.RuntimeProxyStatus_RUNTIME_PROXY_STATUS_ERROR:
		return "error"
	default:
		return "unknown"
	}
}

func verifiedClientCertificate(ctx context.Context) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.New("TLS peer is missing")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return nil, errors.New("client certificate is required")
	}
	if len(info.State.VerifiedChains) == 0 {
		return nil, errors.New("client certificate was not verified")
	}
	return info.State.PeerCertificates[0], nil
}
func certificateMatchesNode(cert *x509.Certificate, nodeID string) error {
	if nodeID == "" {
		return errors.New("Hello node ID is required")
	}
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" && uri.Host == "frp-admin" && uri.Path == "/node/"+nodeID {
			return nil
		}
	}
	for _, name := range cert.DNSNames {
		if subtle.ConstantTimeCompare([]byte(name), []byte(nodeID)) == 1 {
			return nil
		}
	}
	return errors.New("client certificate identity does not match Hello node ID")
}

func validRotationRequestID(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}
func protoRole(role agentv1.NodeRole) string {
	switch role {
	case agentv1.NodeRole_NODE_ROLE_CLIENT:
		return "client"
	case agentv1.NodeRole_NODE_ROLE_SERVER:
		return "server"
	default:
		return ""
	}
}
func serviceState(v agentv1.ServiceState) string {
	switch v {
	case agentv1.ServiceState_SERVICE_STATE_ACTIVE:
		return "active"
	case agentv1.ServiceState_SERVICE_STATE_INACTIVE:
		return "inactive"
	case agentv1.ServiceState_SERVICE_STATE_FAILED:
		return "failed"
	case agentv1.ServiceState_SERVICE_STATE_ACTIVATING:
		return "activating"
	case agentv1.ServiceState_SERVICE_STATE_DEACTIVATING:
		return "deactivating"
	default:
		return "unknown"
	}
}
