package risk

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/agentgateway"
	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/events"
	"github.com/frp-admin/frp-admin/server/internal/store"
	"github.com/frp-admin/frp-admin/server/internal/task"
	"github.com/google/uuid"
)

const (
	RestrictConfigPermissions = "restrict_config_permissions"
	BindAdminAPILoopback      = "bind_admin_api_loopback"
)

type Service struct {
	store   store.Store
	gateway agentgateway.Gateway
	tasks   *task.Service
	events  *events.Bus
	now     func() time.Time
	configs ConfigRevisionDeriver
}

type ConfigRevisionDeriver interface {
	PrepareAdminLoopbackRevision(context.Context, string, string) (domain.ConfigRevision, agentgateway.ConfigMaterial, error)
}

func New(s store.Store, gateway agentgateway.Gateway, tasks *task.Service, bus *events.Bus, configs ...ConfigRevisionDeriver) *Service {
	service := &Service{store: s, gateway: gateway, tasks: tasks, events: bus, now: time.Now}
	if len(configs) > 0 {
		service.configs = configs[0]
	}
	return service
}

func (s *Service) List(ctx context.Context, filter domain.DeploymentRiskFilter, limit int, cursor string) (domain.Page[domain.DeploymentRisk], error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	return s.store.ListDeploymentRisks(ctx, filter, limit, cursor)
}

func (s *Service) Scan(ctx context.Context, nodeID, actor, idempotency string) (domain.Task, error) {
	if strings.TrimSpace(idempotency) == "" {
		return domain.Task{}, ErrIdempotencyRequired
	}
	if existing, err := s.store.TaskByIdempotency(ctx, nodeID, idempotency); err == nil {
		if existing.Type != "risk_scan" || existing.RequestedBy != actor {
			return domain.Task{}, store.ErrConflict
		}
		return existing, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return domain.Task{}, err
	}
	node, err := s.store.NodeByID(ctx, nodeID)
	if err != nil {
		return domain.Task{}, err
	}
	if node.Observation == nil || !hasCapability(node.Observation.Capabilities, "risk.scan") {
		return domain.Task{}, ErrCapabilityUnavailable
	}
	created, err := s.tasks.InspectRisk(ctx, nodeID, actor, idempotency)
	if errors.Is(err, store.ErrConflict) {
		if existing, lookupErr := s.store.TaskByIdempotency(ctx, nodeID, idempotency); lookupErr == nil && existing.Type == "risk_scan" && existing.RequestedBy == actor {
			return existing, nil
		}
	}
	return created, err
}

type RepairRequest struct {
	Action               string
	MaintenanceConfirmed bool
}
type repairPayload struct {
	FindingID, Kind, Action, ExpectedResourceFingerprint, CandidateSHA256 string
	MaintenanceConfirmed                                                  bool
}

func AllowedActions(kind string) []string {
	switch kind {
	case "config_token_permissions":
		return []string{RestrictConfigPermissions}
	case "admin_api_non_loopback":
		return []string{BindAdminAPILoopback}
	default:
		return []string{}
	}
}

func (s *Service) Repair(ctx context.Context, findingID string, request RepairRequest, actor, role, idempotency string) (domain.Task, error) {
	if strings.TrimSpace(idempotency) == "" {
		return domain.Task{}, ErrIdempotencyRequired
	}
	finding, err := s.store.DeploymentRiskByID(ctx, findingID)
	if err != nil {
		return domain.Task{}, err
	}
	request.Action = strings.TrimSpace(request.Action)
	allowed := AllowedActions(finding.Kind)
	if len(allowed) != 1 || request.Action != allowed[0] {
		return domain.Task{}, errors.New("repair action is not allowed for this finding")
	}
	if request.Action == BindAdminAPILoopback {
		if role != "admin" {
			return domain.Task{}, ErrAdminRequired
		}
		if !request.MaintenanceConfirmed {
			return domain.Task{}, ErrMaintenanceConfirmationRequired
		}
	}
	node, err := s.store.NodeByID(ctx, finding.NodeID)
	if err != nil {
		return domain.Task{}, err
	}
	if existing, lookupErr := s.store.TaskByIdempotency(ctx, node.ID, idempotency); lookupErr == nil {
		if !taskMatchesRepair(existing, finding.ID, request, actor) {
			return domain.Task{}, store.ErrConflict
		}
		return existing, nil
	} else if !errors.Is(lookupErr, store.ErrNotFound) {
		return domain.Task{}, lookupErr
	}
	if node.ManagementMode != "managed" {
		return domain.Task{}, store.ErrObserveOnly
	}
	requiredCapability := "risk.repair.config_permissions"
	if request.Action == BindAdminAPILoopback {
		requiredCapability = "risk.repair.admin_loopback"
	}
	if node.Observation == nil || !hasCapability(node.Observation.Capabilities, requiredCapability) {
		return domain.Task{}, ErrCapabilityUnavailable
	}
	if finding.State != "open" {
		return domain.Task{}, store.ErrConflict
	}
	if request.Action == BindAdminAPILoopback && node.Role != "server" {
		return domain.Task{}, store.ErrConflict
	}
	if !validSHA256(finding.ResourceFingerprint) {
		return domain.Task{}, ErrRescanRequired
	}
	var material agentgateway.ConfigMaterial
	var candidate *domain.ConfigRevision
	if request.Action == BindAdminAPILoopback {
		if s.configs == nil || node.DesiredRevisionID == nil {
			return domain.Task{}, ErrDesiredRevisionRequired
		}
		revision, preparedMaterial, deriveErr := s.configs.PrepareAdminLoopbackRevision(ctx, node.ID, actor)
		if deriveErr != nil {
			return domain.Task{}, deriveErr
		}
		candidate = &revision
		material = preparedMaterial
	}
	payload, _ := json.Marshal(repairPayload{FindingID: finding.ID, Kind: finding.Kind, Action: request.Action, MaintenanceConfirmed: request.MaintenanceConfirmed, ExpectedResourceFingerprint: finding.ResourceFingerprint, CandidateSHA256: material.SHA256})
	now := s.now().UTC()
	expires := now.Add(10 * time.Minute)
	t := domain.Task{ID: uuid.Must(uuid.NewV7()).String(), Type: "risk_repair", State: "queued", NodeID: finding.NodeID, IdempotencyKey: idempotency, RequestedBy: actor, Payload: string(payload), ExpiresAt: &expires, CreatedAt: now, UpdatedAt: now}
	if candidate != nil {
		t.ConfigRevisionID = &candidate.ID
		t.ExpectedRevisionID = node.DesiredRevisionID
	}
	step := domain.TaskStep{ID: uuid.Must(uuid.NewV7()).String(), TaskID: t.ID, Name: "risk_repair", State: "queued", Attempt: 1, CreatedAt: now, UpdatedAt: now}
	mutationCtx := store.WithMutationAction(ctx, "deployment_risk.repair", "deployment-risk/"+finding.ID)
	if candidate != nil {
		err = s.store.CreateDerivedDeploymentRiskRepairTask(mutationCtx, finding.ID, *candidate, t, step)
	} else {
		err = s.store.CreateDeploymentRiskRepairTask(mutationCtx, finding.ID, t, step)
	}
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			if existing, lookupErr := s.store.TaskByIdempotency(ctx, node.ID, idempotency); lookupErr == nil && taskMatchesRepair(existing, finding.ID, request, actor) {
				return existing, nil
			}
		}
		return domain.Task{}, err
	}
	if s.events != nil {
		s.events.Publish(events.Event{ID: t.ID, Type: "task.created", Data: []byte(`{}`)})
	}
	if s.gateway == nil || !s.gateway.Connected(t.NodeID) {
		return s.store.TaskByID(ctx, t.ID)
	}
	if err = s.store.UpdateTask(ctx, t.ID, "dispatched", "", "", "dispatched", "", now); err != nil {
		return domain.Task{}, err
	}
	cmd := agentgateway.Command{ID: t.ID, NodeID: t.NodeID, Type: t.Type, RiskFindingID: finding.ID, RiskKind: finding.Kind, RiskAction: request.Action, RiskResourceFingerprint: finding.ResourceFingerprint, MaintenanceConfirmed: request.MaintenanceConfirmed, ExpiresAt: expires}
	if candidate != nil {
		cmd.Revision, cmd.SHA256, cmd.Payload, cmd.Strategy = candidate.ID, material.SHA256, material.Content, material.Strategy
	}
	if err = s.gateway.Dispatch(ctx, cmd); err != nil {
		_ = s.store.UpdateTask(ctx, t.ID, "queued", "", "", "queued", "", s.now())
		if !errors.Is(err, agentgateway.ErrOffline) {
			return domain.Task{}, err
		}
	}
	return s.store.TaskByID(ctx, t.ID)
}

var (
	ErrAdminRequired                   = errors.New("administrator role is required")
	ErrMaintenanceConfirmationRequired = errors.New("maintenance impact confirmation is required")
	ErrIdempotencyRequired             = errors.New("Idempotency-Key is required")
	ErrRescanRequired                  = errors.New("a fresh risk scan with resource fingerprint is required")
	ErrDesiredRevisionRequired         = errors.New("an in-sync managed desired revision is required")
	ErrCapabilityUnavailable           = errors.New("agent capability is unavailable")
)

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func taskMatchesRepair(task domain.Task, findingID string, request RepairRequest, actor string) bool {
	if task.Type != "risk_repair" || task.RequestedBy != actor {
		return false
	}
	var payload repairPayload
	return json.Unmarshal([]byte(task.Payload), &payload) == nil && payload.FindingID == findingID && payload.Action == request.Action && payload.MaintenanceConfirmed == request.MaintenanceConfirmed
}

func hasCapability(raw, expected string) bool {
	var values []string
	if json.Unmarshal([]byte(raw), &values) != nil {
		return false
	}
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
