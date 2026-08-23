package service

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

type invocation struct {
	name string
	args []string
}

type leakingRunner struct{ secret string }

func (r leakingRunner) CombinedOutput(context.Context, string, ...string) ([]byte, error) {
	return []byte(r.secret), errors.New("exit status 1")
}

type recordingRunner struct{ calls []invocation }

func (r *recordingRunner) CombinedOutput(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, invocation{name: name, args: append([]string(nil), args...)})
	return nil, nil
}

type outputRunner struct{ output string }

func (r outputRunner) CombinedOutput(context.Context, string, ...string) ([]byte, error) {
	return []byte(r.output), nil
}

func TestApplyConfigStrategyUsesFixedCommands(t *testing.T) {
	runner := &recordingRunner{}
	s := NewSystemdWithRunner("frpc.service", "/opt/frp/frpc", "/etc/frp/frpc.toml", "client", runner)
	if err := s.ApplyConfigStrategy(context.Background(), "reload"); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyConfigStrategy(context.Background(), "restart"); err != nil {
		t.Fatal(err)
	}
	want := []invocation{
		{name: "/opt/frp/frpc", args: []string{"reload", "-c", "/etc/frp/frpc.toml"}},
		{name: "systemctl", args: []string{"reset-failed", "frpc.service"}},
		{name: "systemctl", args: []string{"restart", "frpc.service"}},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls=%v want=%v", runner.calls, want)
	}
}

func TestServerRejectsReload(t *testing.T) {
	runner := &recordingRunner{}
	s := NewSystemdWithRunner("frps.service", "/opt/frp/frps", "/etc/frp/frps.toml", "server", runner)
	if err := s.ApplyConfigStrategy(context.Background(), "reload"); err == nil {
		t.Fatal("expected reload rejection")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unexpected command: %v", runner.calls)
	}
}

func TestServiceCommandOutputIsNotReturned(t *testing.T) {
	secret := "token=top-secret"
	s := NewSystemdWithRunner("frpc.service", "/opt/frp/frpc", "/etc/frp/frpc.toml", "client", leakingRunner{secret: secret})
	for _, operation := range []func() error{
		func() error { return s.ApplyConfigStrategy(context.Background(), "reload") },
		func() error {
			_, err := s.Act(context.Background(), agentv1.ServiceAction_SERVICE_ACTION_RESTART)
			return err
		},
	} {
		if err := operation(); err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("unsafe service error=%v", err)
		}
	}
}

func TestControllableRejectsIncompleteStatus(t *testing.T) {
	for _, output := range []string{
		"ActiveState=\nSubState=running\n",
		"ActiveState=active\nSubState=\n",
	} {
		s := NewSystemdWithRunner("frpc.service", "/opt/frp/bin/frpc", "/etc/frp/frpc.toml", "client", outputRunner{output: output})
		if err := s.Controllable(context.Background()); err == nil {
			t.Fatalf("incomplete status accepted: %q", output)
		}
	}
}

func TestStopClearsFailedStateBeforeStatus(t *testing.T) {
	runner := &recordingRunner{}
	s := NewSystemdWithRunner("frpc.service", "/opt/frp/bin/frpc", "/etc/frp/frpc.toml", "client", runner)
	_, _ = s.Act(context.Background(), agentv1.ServiceAction_SERVICE_ACTION_STOP)
	want := []invocation{
		{name: "systemctl", args: []string{"stop", "frpc.service"}},
		{name: "systemctl", args: []string{"reset-failed", "frpc.service"}},
		{name: "systemctl", args: []string{"show", "frpc.service", "--property=ActiveState,SubState,ExecMainPID,ExecMainStatus", "--no-pager"}},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls=%v want=%v", runner.calls, want)
	}
}
