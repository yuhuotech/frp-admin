package service

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

type Manager interface {
	Status(context.Context) (*agentv1.ServiceStatus, error)
	Act(context.Context, agentv1.ServiceAction) (*agentv1.ServiceStatus, error)
}

type Lifecycle interface {
	Manager
	ApplyConfigStrategy(context.Context, string) error
	Healthy(context.Context) error
	Controllable(context.Context) error
	Stop(context.Context) error
	Start(context.Context) error
}

type Runner interface {
	CombinedOutput(context.Context, string, ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) CombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type Systemd struct {
	serviceName, binaryPath, configPath, role string
	runner                                    Runner
}

func NewSystemd(serviceName, binaryPath, configPath, role string) *Systemd {
	return NewSystemdWithRunner(serviceName, binaryPath, configPath, role, execRunner{})
}

func NewSystemdWithRunner(serviceName, binaryPath, configPath, role string, runner Runner) *Systemd {
	return &Systemd{serviceName: serviceName, binaryPath: binaryPath, configPath: configPath, role: role, runner: runner}
}

func (s *Systemd) Status(ctx context.Context) (*agentv1.ServiceStatus, error) {
	out, err := s.runner.CombinedOutput(ctx, "systemctl", "show", s.serviceName,
		"--property=ActiveState,SubState,ExecMainPID,ExecMainStatus", "--no-pager")
	if err != nil {
		return nil, fmt.Errorf("systemctl show: %w", err)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			fields[k] = v
		}
	}
	pid, _ := strconv.ParseInt(fields["ExecMainPID"], 10, 64)
	exit, _ := strconv.ParseInt(fields["ExecMainStatus"], 10, 32)
	return &agentv1.ServiceStatus{State: mapState(fields["ActiveState"]), SubState: fields["SubState"], MainPid: pid, ExitCode: int32(exit)}, nil
}

func (s *Systemd) Act(ctx context.Context, action agentv1.ServiceAction) (*agentv1.ServiceStatus, error) {
	var verb string
	switch action {
	case agentv1.ServiceAction_SERVICE_ACTION_STATUS:
		return s.Status(ctx)
	case agentv1.ServiceAction_SERVICE_ACTION_START:
		verb = "start"
	case agentv1.ServiceAction_SERVICE_ACTION_STOP:
		verb = "stop"
	case agentv1.ServiceAction_SERVICE_ACTION_RESTART:
		verb = "restart"
	default:
		return nil, fmt.Errorf("unsupported service action %s", action)
	}
	if verb == "start" || verb == "restart" {
		if _, err := s.runner.CombinedOutput(ctx, "systemctl", "reset-failed", s.serviceName); err != nil {
			return nil, fmt.Errorf("systemctl reset-failed failed")
		}
	}
	if _, err := s.runner.CombinedOutput(ctx, "systemctl", verb, s.serviceName); err != nil {
		return nil, fmt.Errorf("systemctl %s failed", verb)
	}
	if verb == "stop" {
		if _, err := s.runner.CombinedOutput(ctx, "systemctl", "reset-failed", s.serviceName); err != nil {
			return nil, fmt.Errorf("systemctl reset-failed failed")
		}
	}
	return s.Status(ctx)
}

func (s *Systemd) ApplyConfigStrategy(ctx context.Context, strategy string) error {
	var verb string
	switch strategy {
	case "reload":
		if s.role != "client" {
			return fmt.Errorf("reload is only supported for frpc")
		}
		if _, err := s.runner.CombinedOutput(ctx, s.binaryPath, "reload", "-c", s.configPath); err != nil {
			return fmt.Errorf("frpc reload failed")
		}
		return nil
	case "restart":
		verb = "restart"
	default:
		return fmt.Errorf("unsupported config strategy %q", strategy)
	}
	if verb == "restart" {
		if _, err := s.runner.CombinedOutput(ctx, "systemctl", "reset-failed", s.serviceName); err != nil {
			return fmt.Errorf("systemctl reset-failed failed")
		}
	}
	if _, err := s.runner.CombinedOutput(ctx, "systemctl", verb, s.serviceName); err != nil {
		return fmt.Errorf("systemctl %s failed", verb)
	}
	return nil
}

func (s *Systemd) Healthy(ctx context.Context) error {
	status, err := s.Status(ctx)
	if err != nil {
		return err
	}
	if status.GetState() != agentv1.ServiceState_SERVICE_STATE_ACTIVE {
		return fmt.Errorf("service is %s (%s)", status.GetState(), status.GetSubState())
	}
	return nil
}

func (s *Systemd) Controllable(ctx context.Context) error {
	status, err := s.Status(ctx)
	if err != nil {
		return err
	}
	if status.GetState() == agentv1.ServiceState_SERVICE_STATE_UNKNOWN || status.GetSubState() == "" {
		return fmt.Errorf("systemd status is incomplete")
	}
	return nil
}

func (s *Systemd) Stop(ctx context.Context) error {
	_, err := s.Act(ctx, agentv1.ServiceAction_SERVICE_ACTION_STOP)
	return err
}

func (s *Systemd) Start(ctx context.Context) error {
	_, err := s.Act(ctx, agentv1.ServiceAction_SERVICE_ACTION_START)
	return err
}

func mapState(s string) agentv1.ServiceState {
	switch s {
	case "active":
		return agentv1.ServiceState_SERVICE_STATE_ACTIVE
	case "inactive":
		return agentv1.ServiceState_SERVICE_STATE_INACTIVE
	case "failed":
		return agentv1.ServiceState_SERVICE_STATE_FAILED
	case "activating":
		return agentv1.ServiceState_SERVICE_STATE_ACTIVATING
	case "deactivating":
		return agentv1.ServiceState_SERVICE_STATE_DEACTIVATING
	default:
		return agentv1.ServiceState_SERVICE_STATE_UNKNOWN
	}
}
