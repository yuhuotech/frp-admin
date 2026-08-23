package roothelper

import (
	"context"
	"reflect"
	"testing"

	"github.com/frp-admin/frp-admin/agent/internal/service"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

type lifecycleHelper struct{ requests []Request }

func (h *lifecycleHelper) Execute(_ context.Context, request Request) (Response, error) {
	h.requests = append(h.requests, request)
	state := agentv1.ServiceState_SERVICE_STATE_ACTIVE
	if request.Operation == OperationServiceStop {
		state = agentv1.ServiceState_SERVICE_STATE_INACTIVE
	}
	return Response{ServiceStatus: &agentv1.ServiceStatus{State: state}}, nil
}

type statusRunner struct{}

func (statusRunner) CombinedOutput(_ context.Context, name string, args ...string) ([]byte, error) {
	return []byte("ActiveState=active\nSubState=running\nExecMainPID=42\nExecMainStatus=0\n"), nil
}

func TestServiceLifecycleUsesTypedHelperMutations(t *testing.T) {
	helper := &lifecycleHelper{}
	local := service.NewSystemdWithRunner("frpc.service", "/opt/frp/bin/frpc", "/etc/frp/frpc.toml", "client", statusRunner{})
	lifecycle := NewServiceLifecycle(local, helper)
	ctx := context.Background()
	if _, err := lifecycle.Act(ctx, agentv1.ServiceAction_SERVICE_ACTION_START); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.ApplyConfigStrategy(ctx, "restart"); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Start(ctx); err != nil {
		t.Fatal(err)
	}
	want := []Request{
		{Operation: OperationServiceStart},
		{Operation: OperationServiceRestart},
		{Operation: OperationServiceStop},
		{Operation: OperationServiceStart},
	}
	if !reflect.DeepEqual(helper.requests, want) {
		t.Fatalf("requests=%+v want=%+v", helper.requests, want)
	}
}

func TestServiceLifecycleKeepsStatusAndReloadLocal(t *testing.T) {
	helper := &lifecycleHelper{}
	local := service.NewSystemdWithRunner("frpc.service", "/opt/frp/bin/frpc", "/etc/frp/frpc.toml", "client", statusRunner{})
	lifecycle := NewServiceLifecycle(local, helper)
	if _, err := lifecycle.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.ApplyConfigStrategy(context.Background(), "reload"); err != nil {
		t.Fatal(err)
	}
	if len(helper.requests) != 0 {
		t.Fatalf("read-only status or unprivileged reload reached helper: %+v", helper.requests)
	}
}
