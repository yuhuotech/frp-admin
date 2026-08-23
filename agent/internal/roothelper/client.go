package roothelper

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/frp-admin/frp-admin/agent/internal/securitycheck"
	"github.com/frp-admin/frp-admin/agent/internal/service"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

type Client struct {
	SocketPath string
	Timeout    time.Duration
}

func (c Client) Collect(ctx context.Context) securitycheck.Result {
	response, err := c.Execute(ctx, Request{Operation: OperationScan})
	if err != nil || response.ErrorCode != 0 {
		return securitycheck.Result{ErrorCode: "PRIVILEGED_SCAN_UNAVAILABLE"}
	}
	return securitycheck.Result{Findings: response.Findings, CompletedKinds: response.CompletedKinds,
		Complete: len(response.ScanErrorCode) == 0, ErrorCode: response.ScanErrorCode}
}

func (c Client) ReadConfig(ctx context.Context) ([]byte, error) {
	response, err := c.Execute(ctx, Request{Operation: OperationReadConfig})
	if err != nil {
		return nil, err
	}
	if response.ErrorCode != 0 {
		return nil, errors.New("privileged config read failed")
	}
	return response.ConfigContent, nil
}

func (c Client) Probe(ctx context.Context) error {
	response, err := c.Execute(ctx, Request{Operation: OperationProbe})
	if err != nil {
		return err
	}
	if response.ErrorCode != 0 {
		return errors.New("privileged helper probe failed")
	}
	return nil
}

func (c Client) ProbeService(ctx context.Context) error {
	response, err := c.Execute(ctx, Request{Operation: OperationProbeService})
	if err != nil {
		return err
	}
	if response.ErrorCode != 0 || response.ServiceStatus == nil {
		return errors.New("privileged service helper probe failed")
	}
	return nil
}

type serviceHelper interface {
	Execute(context.Context, Request) (Response, error)
}

// ServiceLifecycle keeps read-only status local and sends only typed mutations
// through the privileged helper.
type ServiceLifecycle struct {
	local  service.Lifecycle
	helper serviceHelper
}

func NewServiceLifecycle(local service.Lifecycle, helper serviceHelper) *ServiceLifecycle {
	return &ServiceLifecycle{local: local, helper: helper}
}

func (s *ServiceLifecycle) Status(ctx context.Context) (*agentv1.ServiceStatus, error) {
	return s.local.Status(ctx)
}

func (s *ServiceLifecycle) Act(ctx context.Context, action agentv1.ServiceAction) (*agentv1.ServiceStatus, error) {
	if action == agentv1.ServiceAction_SERVICE_ACTION_STATUS {
		return s.local.Status(ctx)
	}
	operation := ""
	switch action {
	case agentv1.ServiceAction_SERVICE_ACTION_START:
		operation = OperationServiceStart
	case agentv1.ServiceAction_SERVICE_ACTION_STOP:
		operation = OperationServiceStop
	case agentv1.ServiceAction_SERVICE_ACTION_RESTART:
		operation = OperationServiceRestart
	default:
		return nil, errors.New("unsupported service action")
	}
	response, err := s.helper.Execute(ctx, Request{Operation: operation})
	if err != nil {
		return nil, err
	}
	if response.ErrorCode != 0 || response.ServiceStatus == nil {
		return nil, errors.New("privileged service operation failed")
	}
	return response.ServiceStatus, nil
}

func (s *ServiceLifecycle) ApplyConfigStrategy(ctx context.Context, strategy string) error {
	if strategy == "reload" {
		return s.local.ApplyConfigStrategy(ctx, strategy)
	}
	if strategy != "restart" {
		return errors.New("unsupported config strategy")
	}
	_, err := s.Act(ctx, agentv1.ServiceAction_SERVICE_ACTION_RESTART)
	return err
}

func (s *ServiceLifecycle) Healthy(ctx context.Context) error      { return s.local.Healthy(ctx) }
func (s *ServiceLifecycle) Controllable(ctx context.Context) error { return s.local.Controllable(ctx) }
func (s *ServiceLifecycle) Stop(ctx context.Context) error {
	_, err := s.Act(ctx, agentv1.ServiceAction_SERVICE_ACTION_STOP)
	return err
}
func (s *ServiceLifecycle) Start(ctx context.Context) error {
	_, err := s.Act(ctx, agentv1.ServiceAction_SERVICE_ACTION_START)
	return err
}

func (c Client) InspectSHA(ctx context.Context) (string, error) {
	response, err := c.Execute(ctx, Request{Operation: OperationInspect})
	if err != nil || response.ErrorCode != 0 || len(response.ResourceSHA) != 64 {
		return "", errors.New("privileged config inspection failed")
	}
	return response.ResourceSHA, nil
}

func (c Client) Execute(ctx context.Context, request Request) (Response, error) {
	if c.SocketPath == "" {
		return Response{}, errors.New("privileged helper socket is not configured")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return Response{}, errors.New("privileged helper is unavailable")
	}
	defer connection.Close()
	stopCancellation := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopCancellation()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	encoder := json.NewEncoder(connection)
	if err := encoder.Encode(request); err != nil {
		return Response{}, errors.New("privileged helper request failed")
	}
	halfCloser, ok := connection.(interface{ CloseWrite() error })
	if !ok || halfCloser.CloseWrite() != nil {
		return Response{}, errors.New("privileged helper request could not be finalized")
	}
	var response Response
	decoder := json.NewDecoder(connection)
	if err := decoder.Decode(&response); err != nil {
		return Response{}, errors.New("privileged helper response failed")
	}
	return response, nil
}
