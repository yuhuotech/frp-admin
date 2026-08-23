package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/frp-admin/frp-admin/agent/internal/configmgr"
	"github.com/frp-admin/frp-admin/agent/internal/frpadmin"
	"github.com/frp-admin/frp-admin/agent/internal/inventory"
	"github.com/frp-admin/frp-admin/agent/internal/journal"
	"github.com/frp-admin/frp-admin/agent/internal/operation"
	"github.com/frp-admin/frp-admin/agent/internal/remediation"
	"github.com/frp-admin/frp-admin/agent/internal/service"
	"github.com/frp-admin/frp-admin/agent/internal/upgrader"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
	"google.golang.org/protobuf/proto"
)

var (
	ErrCommandCancelled = errors.New("command cancelled")
	ErrCommandExpired   = errors.New("command expired")
)

type Executor struct {
	journal    *journal.Journal
	inventory  inventory.Collector
	services   service.Manager
	configs    *configmgr.Manager
	upgrades   *upgrader.Manager
	runtime    frpadmin.Collector
	remediator RiskRemediator
	now        func() time.Time
	operations *operation.Lock
}

type RiskRemediator interface {
	Repair(context.Context, *agentv1.RepairDeploymentRiskCommand) (*agentv1.RepairDeploymentRiskResult, error)
}

func New(j *journal.Journal, inv inventory.Collector, services service.Manager) *Executor {
	return &Executor{journal: j, inventory: inv, services: services, operations: &operation.Lock{}, now: time.Now}
}

func (e *Executor) WithConfigManager(configs *configmgr.Manager) *Executor {
	e.configs = configs
	return e
}

func (e *Executor) WithUpgrader(upgrades *upgrader.Manager) *Executor {
	e.upgrades = upgrades
	return e
}

func (e *Executor) WithRuntimeCollector(runtime frpadmin.Collector) *Executor {
	e.runtime = runtime
	return e
}

func (e *Executor) WithRemediator(remediator RiskRemediator) *Executor {
	e.remediator = remediator
	return e
}

func (e *Executor) CollectInventory(ctx context.Context) (*agentv1.Inventory, error) {
	return e.inventory.Collect(ctx)
}

func (e *Executor) Cached(c *agentv1.Command) (*agentv1.CommandResult, bool, error) {
	if c.GetCommandId() == "" {
		return nil, false, nil
	}
	if r, ok, err := e.journal.Get("command:" + c.GetCommandId()); err != nil || ok {
		return r, ok, err
	}
	if c.GetIdempotencyKey() != "" {
		return e.journal.Get("idempotency:" + c.GetIdempotencyKey())
	}
	return nil, false, nil
}

func (e *Executor) Execute(ctx context.Context, c *agentv1.Command) *agentv1.CommandResult {
	cached, ok, cacheErr := e.Cached(c)
	if cacheErr != nil {
		now := e.now().UnixMilli()
		return &agentv1.CommandResult{CommandId: c.GetCommandId(), IdempotencyKey: c.GetIdempotencyKey(),
			Status: agentv1.CommandStatus_COMMAND_STATUS_FAILED, ErrorCode: agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED,
			Diagnostic: sanitize(fmt.Sprintf("idempotency journal read failed; command was not executed: %v", cacheErr)), StartedAtUnixMs: now, FinishedAtUnixMs: now}
	}
	if ok {
		replayed := proto.Clone(cached).(*agentv1.CommandResult)
		replayed.CommandId = c.GetCommandId()
		replayed.IdempotencyKey = c.GetIdempotencyKey()
		return replayed
	}
	if isMutation(c) {
		if !e.operations.TryAcquire() {
			result := &agentv1.CommandResult{CommandId: c.GetCommandId(), IdempotencyKey: c.GetIdempotencyKey(),
				Status: agentv1.CommandStatus_COMMAND_STATUS_FAILED, ErrorCode: agentv1.ErrorCode_ERROR_CODE_OPERATION_IN_PROGRESS,
				Diagnostic: "another node mutation is in progress", StartedAtUnixMs: e.now().UnixMilli(), FinishedAtUnixMs: e.now().UnixMilli()}
			return e.persistResult(c, result)
		}
		defer e.operations.Release()
	}
	started := e.now()
	r := &agentv1.CommandResult{CommandId: c.GetCommandId(), IdempotencyKey: c.GetIdempotencyKey(),
		Status: agentv1.CommandStatus_COMMAND_STATUS_FAILED, StartedAtUnixMs: started.UnixMilli()}
	if c.GetCommandId() == "" || c.GetAction() == nil {
		fail(r, agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "command id and action are required")
	} else if c.GetExpiresAtUnixMs() > 0 && started.UnixMilli() > c.GetExpiresAtUnixMs() {
		fail(r, agentv1.ErrorCode_ERROR_CODE_COMMAND_EXPIRED, "command expired")
	} else {
		switch action := c.GetAction().(type) {
		case *agentv1.Command_Inspect:
			inv, err := e.inventory.Collect(ctx)
			if err != nil {
				fail(r, agentv1.ErrorCode_ERROR_CODE_INTERNAL, err.Error())
			} else {
				r.Status = agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED
				r.Output = &agentv1.CommandResult_Inspect{Inspect: &agentv1.InspectResult{Inventory: inv}}
			}
		case *agentv1.Command_Service:
			var status *agentv1.ServiceStatus
			var err error
			if expected := action.Service.GetExpectedState(); expected != agentv1.ServiceState_SERVICE_STATE_UNSPECIFIED {
				status, err = e.services.Status(ctx)
				if err != nil {
					fail(r, agentv1.ErrorCode_ERROR_CODE_SERVICE_OPERATION_FAILED, err.Error())
					break
				}
				if status.GetState() != expected {
					fail(r, agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "service state precondition failed")
					break
				}
			}
			status, err = e.services.Act(ctx, action.Service.GetAction())
			if err != nil {
				fail(r, agentv1.ErrorCode_ERROR_CODE_SERVICE_OPERATION_FAILED, err.Error())
			} else {
				r.Status = agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED
				r.Output = &agentv1.CommandResult_Service{Service: &agentv1.ServiceResult{Status: status}}
			}
		case *agentv1.Command_ApplyConfig:
			if e.configs == nil {
				fail(r, agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED_COMMAND, "config manager is unavailable")
				break
			}
			err := e.configs.Apply(ctx, action.ApplyConfig.GetRevision(), action.ApplyConfig.GetSha256(),
				action.ApplyConfig.GetContent(), action.ApplyConfig.GetStrategy())
			if err != nil {
				code := configErrorCode(err)
				fail(r, code, configDiagnostic(code))
			} else {
				r.Status = agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED
			}
		case *agentv1.Command_RollbackConfig:
			if e.configs == nil {
				fail(r, agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED_COMMAND, "config manager is unavailable")
				break
			}
			err := e.configs.Rollback(ctx, action.RollbackConfig.GetTargetRevision(), "restart")
			if err != nil {
				code := configErrorCode(err)
				fail(r, code, configDiagnostic(code))
			} else {
				r.Status = agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED
			}
		case *agentv1.Command_UpgradeFrp:
			if e.upgrades == nil {
				fail(r, agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED_COMMAND, "upgrader is unavailable")
				break
			}
			err := e.upgrades.Upgrade(ctx, action.UpgradeFrp.GetVersion(), action.UpgradeFrp.GetArtifactUrl(), action.UpgradeFrp.GetSha256())
			if err != nil {
				code := upgradeErrorCode(err)
				fail(r, code, upgradeDiagnostic(code))
			} else {
				r.Status = agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED
			}
		case *agentv1.Command_CollectRuntime:
			if e.runtime == nil {
				fail(r, agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED_COMMAND, "runtime collector is unavailable")
				break
			}
			snapshot, err := e.runtime.Collect(ctx, action.CollectRuntime.GetDetailLevel())
			if err != nil {
				fail(r, runtimeErrorCode(err), err.Error())
			} else {
				r.Status = agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED
				r.Output = &agentv1.CommandResult_Runtime{Runtime: &agentv1.RuntimeResult{Snapshot: snapshot}}
			}
		case *agentv1.Command_RepairDeploymentRisk:
			if e.remediator == nil {
				fail(r, agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED_COMMAND, "deployment risk remediation is unavailable")
				break
			}
			repair, err := e.remediator.Repair(ctx, action.RepairDeploymentRisk)
			if err != nil {
				if repair != nil {
					r.Output = &agentv1.CommandResult_RepairDeploymentRisk{RepairDeploymentRisk: repair}
				} else {
					var repairErr *remediation.Error
					if errors.As(err, &repairErr) && repairErr.Result != nil {
						r.Output = &agentv1.CommandResult_RepairDeploymentRisk{RepairDeploymentRisk: repairErr.Result}
					}
				}
				code := remediationErrorCode(err)
				fail(r, code, remediationDiagnostic(code))
			} else {
				r.Status = agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED
				r.Output = &agentv1.CommandResult_RepairDeploymentRisk{RepairDeploymentRisk: repair}
			}
		default:
			fail(r, agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED_COMMAND, "command is defined but not supported by this agent build")
		}
	}
	if cause := context.Cause(ctx); errors.Is(cause, ErrCommandCancelled) {
		r.Status = agentv1.CommandStatus_COMMAND_STATUS_CANCELLED
		fail(r, agentv1.ErrorCode_ERROR_CODE_CANCELLED, "command cancelled")
	} else if errors.Is(cause, ErrCommandExpired) {
		r.Status = agentv1.CommandStatus_COMMAND_STATUS_FAILED
		fail(r, agentv1.ErrorCode_ERROR_CODE_COMMAND_EXPIRED, "command expired")
	}
	r.FinishedAtUnixMs = e.now().UnixMilli()
	r.Diagnostic = sanitize(r.Diagnostic)
	return e.persistResult(c, r)
}

func (e *Executor) persistResult(c *agentv1.Command, result *agentv1.CommandResult) *agentv1.CommandResult {
	if c.GetCommandId() == "" {
		return result
	}
	if err := e.journal.Put([]string{"command:" + c.GetCommandId(), "idempotency:" + c.GetIdempotencyKey()}, result); err != nil {
		previous := result.GetStatus().String()
		result.Status = agentv1.CommandStatus_COMMAND_STATUS_FAILED
		result.ErrorCode = agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED
		result.Diagnostic = sanitize(fmt.Sprintf("operation reached %s but idempotency journal persistence failed: %v", previous, err))
	}
	return result
}

func isMutation(c *agentv1.Command) bool {
	switch action := c.GetAction().(type) {
	case *agentv1.Command_ApplyConfig, *agentv1.Command_RollbackConfig, *agentv1.Command_UpgradeFrp, *agentv1.Command_RepairDeploymentRisk:
		return true
	case *agentv1.Command_Service:
		return action.Service.GetAction() != agentv1.ServiceAction_SERVICE_ACTION_STATUS
	default:
		return false
	}
}

func remediationErrorCode(err error) agentv1.ErrorCode {
	var target *remediation.Error
	if errors.As(err, &target) {
		return target.Code
	}
	return agentv1.ErrorCode_ERROR_CODE_INTERNAL
}

func remediationDiagnostic(code agentv1.ErrorCode) string {
	switch code {
	case agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND:
		return "deployment risk repair command is invalid"
	case agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED:
		return "deployment risk repair precondition failed"
	case agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH:
		return "deployment risk repair target is unsafe"
	case agentv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED:
		return "deployment risk repair permission was denied"
	case agentv1.ErrorCode_ERROR_CODE_VERIFY_FAILED:
		return "deployment risk repair verification failed"
	case agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED:
		return "deployment risk repair recovery failed"
	case agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED_COMMAND:
		return "deployment risk repair is unsupported on this node"
	default:
		return "deployment risk repair failed"
	}
}

func configErrorCode(err error) agentv1.ErrorCode {
	var target *configmgr.Error
	if errors.As(err, &target) {
		return target.Code
	}
	return agentv1.ErrorCode_ERROR_CODE_INTERNAL
}

func upgradeErrorCode(err error) agentv1.ErrorCode {
	var target *upgrader.Error
	if errors.As(err, &target) {
		return target.Code
	}
	return agentv1.ErrorCode_ERROR_CODE_INTERNAL
}

func configDiagnostic(code agentv1.ErrorCode) string {
	switch code {
	case agentv1.ErrorCode_ERROR_CODE_VERIFY_FAILED:
		return "candidate configuration verification failed"
	case agentv1.ErrorCode_ERROR_CODE_CHECKSUM_MISMATCH:
		return "candidate configuration checksum mismatch"
	case agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND:
		return "configuration command is invalid"
	case agentv1.ErrorCode_ERROR_CODE_HEALTHCHECK_FAILED:
		return "configuration health check failed"
	case agentv1.ErrorCode_ERROR_CODE_SERVICE_OPERATION_FAILED:
		return "configuration service operation failed"
	default:
		return "configuration operation failed"
	}
}

func upgradeDiagnostic(code agentv1.ErrorCode) string {
	switch code {
	case agentv1.ErrorCode_ERROR_CODE_VERIFY_FAILED:
		return "upgrade candidate configuration verification failed"
	case agentv1.ErrorCode_ERROR_CODE_CHECKSUM_MISMATCH:
		return "upgrade artifact checksum mismatch"
	case agentv1.ErrorCode_ERROR_CODE_HEALTHCHECK_FAILED:
		return "upgrade health check failed"
	case agentv1.ErrorCode_ERROR_CODE_SERVICE_OPERATION_FAILED:
		return "upgrade service operation failed"
	default:
		return "upgrade operation failed"
	}
}

func runtimeErrorCode(err error) agentv1.ErrorCode {
	var target *frpadmin.Error
	if errors.As(err, &target) {
		return target.Code
	}
	return agentv1.ErrorCode_ERROR_CODE_INTERNAL
}

func fail(r *agentv1.CommandResult, code agentv1.ErrorCode, diagnostic string) {
	r.ErrorCode = code
	r.Diagnostic = diagnostic
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) > 1024 {
		return fmt.Sprintf("%.1024s", s)
	}
	return s
}
