//go:build darwin

package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

// Launchd controls a user LaunchAgent without requiring root. The label is
// fixed by the Agent configuration and the plist path is only used to load a
// service that is not currently bootstrapped in the user's GUI domain.
type Launchd struct {
	serviceName, plistPath, binaryPath, configPath, role string
	runner                                               Runner
}

func NewLaunchd(serviceName, plistPath, binaryPath, configPath, role string) *Launchd {
	if plistPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			plistPath = filepath.Join(home, "Library", "LaunchAgents", serviceName+".plist")
		}
	}
	return NewLaunchdWithRunner(serviceName, plistPath, binaryPath, configPath, role, execRunner{})
}

func NewLaunchdWithRunner(serviceName, plistPath, binaryPath, configPath, role string, runner Runner) *Launchd {
	return &Launchd{serviceName: serviceName, plistPath: plistPath, binaryPath: binaryPath, configPath: configPath, role: role, runner: runner}
}

func (s *Launchd) target() string {
	return fmt.Sprintf("gui/%d/%s", os.Getuid(), s.serviceName)
}

func (s *Launchd) domain() string {
	return fmt.Sprintf("gui/%d", os.Getuid())
}

func (s *Launchd) Status(ctx context.Context) (*agentv1.ServiceStatus, error) {
	out, err := s.runner.CombinedOutput(ctx, "launchctl", "print", s.target())
	if err != nil {
		return &agentv1.ServiceStatus{State: agentv1.ServiceState_SERVICE_STATE_INACTIVE, SubState: "not_loaded"}, nil
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if key, value, ok := strings.Cut(line, "="); ok {
			fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	stateText := fields["state"]
	if stateText == "" {
		stateText = fields["state"]
	}
	pid, _ := strconv.ParseInt(fields["pid"], 10, 64)
	exitCode, _ := strconv.ParseInt(fields["last exit code"], 10, 32)
	return &agentv1.ServiceStatus{State: mapLaunchdState(stateText), SubState: stateText, MainPid: pid, ExitCode: int32(exitCode)}, nil
}

func (s *Launchd) Act(ctx context.Context, action agentv1.ServiceAction) (*agentv1.ServiceStatus, error) {
	switch action {
	case agentv1.ServiceAction_SERVICE_ACTION_STATUS:
		return s.Status(ctx)
	case agentv1.ServiceAction_SERVICE_ACTION_START:
		if err := s.ensureLoaded(ctx); err != nil {
			return nil, err
		}
		if _, err := s.runner.CombinedOutput(ctx, "launchctl", "enable", s.target()); err != nil {
			return nil, fmt.Errorf("launchctl enable failed")
		}
		if _, err := s.runner.CombinedOutput(ctx, "launchctl", "kickstart", "-k", s.target()); err != nil {
			return nil, fmt.Errorf("launchctl kickstart failed")
		}
	case agentv1.ServiceAction_SERVICE_ACTION_STOP:
		status, err := s.Status(ctx)
		if err != nil {
			return nil, err
		}
		if status.GetState() == agentv1.ServiceState_SERVICE_STATE_ACTIVE || status.GetMainPid() != 0 {
			if _, err := s.runner.CombinedOutput(ctx, "launchctl", "disable", s.target()); err != nil {
				return nil, fmt.Errorf("launchctl disable failed")
			}
			if _, err := s.runner.CombinedOutput(ctx, "launchctl", "kill", "SIGTERM", s.target()); err != nil {
				return nil, fmt.Errorf("launchctl kill failed")
			}
		}
	case agentv1.ServiceAction_SERVICE_ACTION_RESTART:
		if err := s.ensureLoaded(ctx); err != nil {
			return nil, err
		}
		if _, err := s.runner.CombinedOutput(ctx, "launchctl", "enable", s.target()); err != nil {
			return nil, fmt.Errorf("launchctl enable failed")
		}
		if _, err := s.runner.CombinedOutput(ctx, "launchctl", "kickstart", "-k", s.target()); err != nil {
			return nil, fmt.Errorf("launchctl kickstart failed")
		}
	default:
		return nil, fmt.Errorf("unsupported service action %s", action)
	}
	return s.Status(ctx)
}

func (s *Launchd) ApplyConfigStrategy(ctx context.Context, strategy string) error {
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
		_, err := s.Act(ctx, agentv1.ServiceAction_SERVICE_ACTION_RESTART)
		return err
	default:
		return fmt.Errorf("unsupported config strategy %q", strategy)
	}
}

func (s *Launchd) Healthy(ctx context.Context) error {
	status, err := s.Status(ctx)
	if err != nil {
		return err
	}
	if status.GetState() != agentv1.ServiceState_SERVICE_STATE_ACTIVE {
		return fmt.Errorf("service is %s (%s)", status.GetState(), status.GetSubState())
	}
	return nil
}

func (s *Launchd) Controllable(ctx context.Context) error {
	status, err := s.Status(ctx)
	if err != nil {
		return err
	}
	if status.GetState() == agentv1.ServiceState_SERVICE_STATE_UNKNOWN || status.GetSubState() == "" {
		return fmt.Errorf("launchd status is incomplete")
	}
	return nil
}

func (s *Launchd) Stop(ctx context.Context) error {
	_, err := s.Act(ctx, agentv1.ServiceAction_SERVICE_ACTION_STOP)
	return err
}

func (s *Launchd) Start(ctx context.Context) error {
	_, err := s.Act(ctx, agentv1.ServiceAction_SERVICE_ACTION_START)
	return err
}

func (s *Launchd) ensureLoaded(ctx context.Context) error {
	if _, err := s.runner.CombinedOutput(ctx, "launchctl", "print", s.target()); err == nil {
		return nil
	}
	if s.plistPath == "" {
		return fmt.Errorf("launchd service is not loaded and plist path is not configured")
	}
	if _, err := s.runner.CombinedOutput(ctx, "launchctl", "bootstrap", s.domain(), s.plistPath); err != nil {
		return fmt.Errorf("launchctl bootstrap failed")
	}
	return nil
}

func mapLaunchdState(value string) agentv1.ServiceState {
	switch strings.ToLower(value) {
	case "running", "active":
		return agentv1.ServiceState_SERVICE_STATE_ACTIVE
	case "spawn scheduled", "starting", "activating":
		return agentv1.ServiceState_SERVICE_STATE_ACTIVATING
	case "exited", "failed":
		return agentv1.ServiceState_SERVICE_STATE_FAILED
	case "not running", "inactive", "":
		return agentv1.ServiceState_SERVICE_STATE_INACTIVE
	default:
		return agentv1.ServiceState_SERVICE_STATE_UNKNOWN
	}
}
