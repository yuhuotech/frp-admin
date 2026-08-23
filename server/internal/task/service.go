package task

import (
	"context"
	"errors"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/agentcap"
	"github.com/frp-admin/frp-admin/server/internal/agentgateway"
	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/events"
	"github.com/frp-admin/frp-admin/server/internal/metrics"
	"github.com/frp-admin/frp-admin/server/internal/store"
	"github.com/google/uuid"
)

type Service struct {
	store          store.Store
	gateway        agentgateway.Gateway
	events         *events.Bus
	now            func() time.Time
	inspectTimeout time.Duration
	serviceTimeout time.Duration
	alerter        AlertSink
}

type AlertSink interface {
	Trigger(context.Context, string, string, string, string)
}

func New(s store.Store, gateway agentgateway.Gateway, bus *events.Bus, alerters ...AlertSink) *Service {
	v := &Service{store: s, gateway: gateway, events: bus, now: time.Now, inspectTimeout: 2 * time.Minute, serviceTimeout: 2 * time.Minute}
	if len(alerters) > 0 {
		v.alerter = alerters[0]
	}
	return v
}
func (s *Service) SetTimeouts(inspect, service time.Duration) {
	if inspect > 0 {
		s.inspectTimeout = inspect
	}
	if service > 0 {
		s.serviceTimeout = service
	}
}
func (s *Service) List(ctx context.Context, limit int, cursor, state, nodeID string) (domain.Page[domain.Task], error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	return s.store.ListTasks(ctx, limit, cursor, state, nodeID)
}
func (s *Service) Get(ctx context.Context, id string) (domain.Task, error) {
	return s.store.TaskByID(ctx, id)
}
func (s *Service) Inspect(ctx context.Context, nodeID, actor, idempotencyKey string) (domain.Task, error) {
	return s.inspect(ctx, nodeID, actor, idempotencyKey, "inspect", "node.inspect")
}

func (s *Service) InspectRisk(ctx context.Context, nodeID, actor, idempotencyKey string) (domain.Task, error) {
	return s.inspect(ctx, nodeID, actor, idempotencyKey, "risk_scan", "deployment_risk.scan")
}

func (s *Service) inspect(ctx context.Context, nodeID, actor, idempotencyKey, kind, auditAction string) (domain.Task, error) {
	if idempotencyKey == "" {
		idempotencyKey = uuid.NewString()
	} else if existing, found, e := s.replayTask(ctx, nodeID, idempotencyKey, actor, kind); e != nil || found {
		return existing, e
	}
	node, e := s.store.NodeByID(ctx, nodeID)
	if e != nil {
		return domain.Task{}, e
	}
	requiredCapability := "inspect"
	if kind == "risk_scan" {
		requiredCapability = "risk.scan"
	}
	if !agentcap.Has(node, requiredCapability) {
		return domain.Task{}, store.ErrCapabilityUnavailable
	}
	now := s.now().UTC()
	expires := now.Add(s.inspectTimeout)
	t := domain.Task{ID: uuid.Must(uuid.NewV7()).String(), Type: kind, State: "queued", NodeID: nodeID, IdempotencyKey: idempotencyKey, RequestedBy: actor, ExpiresAt: &expires, CreatedAt: now, UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.Must(uuid.NewV7()).String(), TaskID: t.ID, Name: kind, State: "queued", Attempt: 1, CreatedAt: now, UpdatedAt: now}
	if e = s.store.CreateTask(store.WithMutationAction(ctx, auditAction, "node/"+nodeID), t, step); e != nil {
		if errors.Is(e, store.ErrConflict) {
			if existing, found, replayErr := s.replayTask(ctx, nodeID, idempotencyKey, actor, kind); replayErr != nil || found {
				return existing, replayErr
			}
		}
		return domain.Task{}, e
	}
	s.publish(t.ID, "task.created")
	if s.gateway == nil || !s.gateway.Connected(nodeID) {
		return s.store.TaskByID(ctx, t.ID)
	}
	if e := s.store.UpdateTask(ctx, t.ID, "dispatched", "", "", "dispatched", "", s.now()); e != nil {
		return domain.Task{}, e
	}
	if e := s.gateway.Dispatch(ctx, agentgateway.Command{ID: t.ID, NodeID: nodeID, Type: kind, ExpiresAt: expires}); e != nil {
		_ = s.store.UpdateTask(ctx, t.ID, "queued", "", "", "queued", "", s.now())
		if !errors.Is(e, agentgateway.ErrOffline) {
			return domain.Task{}, e
		}
	}
	s.publish(t.ID, "task.updated")
	return s.store.TaskByID(ctx, t.ID)
}

func (s *Service) ServiceAction(ctx context.Context, nodeID, action, actor, idempotencyKey string) (domain.Task, error) {
	switch action {
	case "start", "stop", "restart":
	default:
		return domain.Task{}, errors.New("service action must be start, stop, or restart")
	}
	if idempotencyKey == "" {
		idempotencyKey = uuid.NewString()
	}
	kind := "service_" + action
	if existing, found, e := s.replayTask(ctx, nodeID, idempotencyKey, actor, kind); e != nil || found {
		return existing, e
	}
	node, e := s.store.NodeByID(ctx, nodeID)
	if e != nil {
		return domain.Task{}, e
	}
	if node.ManagementMode != "managed" {
		return domain.Task{}, store.ErrObserveOnly
	}
	if !agentcap.Has(node, "service."+action) {
		return domain.Task{}, store.ErrCapabilityUnavailable
	}
	now := s.now().UTC()
	expires := now.Add(s.serviceTimeout)
	t := domain.Task{ID: uuid.Must(uuid.NewV7()).String(), Type: kind, State: "queued", NodeID: nodeID, IdempotencyKey: idempotencyKey, RequestedBy: actor, Payload: "{}", ExpiresAt: &expires, CreatedAt: now, UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.Must(uuid.NewV7()).String(), TaskID: t.ID, Name: kind, State: "queued", Attempt: 1, CreatedAt: now, UpdatedAt: now}
	if e := s.store.CreateTask(store.WithMutationAction(ctx, "node.service."+action, "node/"+nodeID), t, step); e != nil {
		if errors.Is(e, store.ErrConflict) {
			if existing, found, replayErr := s.replayTask(ctx, nodeID, idempotencyKey, actor, kind); replayErr != nil || found {
				return existing, replayErr
			}
		}
		return domain.Task{}, e
	}
	s.publish(t.ID, "task.created")
	if s.gateway == nil || !s.gateway.Connected(nodeID) {
		return s.store.TaskByID(ctx, t.ID)
	}
	if e := s.store.UpdateTask(ctx, t.ID, "dispatched", "", "", "dispatched", "", now); e != nil {
		return domain.Task{}, e
	}
	if e := s.gateway.Dispatch(ctx, agentgateway.Command{ID: t.ID, NodeID: nodeID, Type: kind, ExpiresAt: expires}); e != nil {
		_ = s.store.UpdateTask(ctx, t.ID, "queued", "", "", "queued", "", s.now())
		if !errors.Is(e, agentgateway.ErrOffline) {
			return domain.Task{}, e
		}
	}
	s.publish(t.ID, "task.updated")
	return s.store.TaskByID(ctx, t.ID)
}
func (s *Service) CollectRuntime(ctx context.Context, nodeID, actor, idempotencyKey string) (domain.Task, error) {
	if idempotencyKey == "" {
		idempotencyKey = uuid.NewString()
	} else if existing, found, e := s.replayTask(ctx, nodeID, idempotencyKey, actor, "collect_runtime"); e != nil || found {
		return existing, e
	}
	node, e := s.store.NodeByID(ctx, nodeID)
	if e != nil {
		return domain.Task{}, e
	}
	if !agentcap.Has(node, "runtime.collect") {
		return domain.Task{}, store.ErrCapabilityUnavailable
	}
	now := s.now().UTC()
	expires := now.Add(s.inspectTimeout)
	kind := "collect_runtime"
	t := domain.Task{ID: uuid.Must(uuid.NewV7()).String(), Type: kind, State: "queued", NodeID: nodeID, IdempotencyKey: idempotencyKey, RequestedBy: actor, Payload: "{}", ExpiresAt: &expires, CreatedAt: now, UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.Must(uuid.NewV7()).String(), TaskID: t.ID, Name: kind, State: "queued", Attempt: 1, CreatedAt: now, UpdatedAt: now}
	if e = s.store.CreateTask(store.WithMutationAction(ctx, "node.runtime.collect", "node/"+nodeID), t, step); e != nil {
		if errors.Is(e, store.ErrConflict) {
			if existing, found, replayErr := s.replayTask(ctx, nodeID, idempotencyKey, actor, kind); replayErr != nil || found {
				return existing, replayErr
			}
		}
		return domain.Task{}, e
	}
	s.publish(t.ID, "task.created")
	if s.gateway == nil || !s.gateway.Connected(nodeID) {
		return s.store.TaskByID(ctx, t.ID)
	}
	if e := s.store.UpdateTask(ctx, t.ID, "dispatched", "", "", "dispatched", "", now); e != nil {
		return domain.Task{}, e
	}
	if e := s.gateway.Dispatch(ctx, agentgateway.Command{ID: t.ID, NodeID: nodeID, Type: kind, ExpiresAt: expires}); e != nil {
		_ = s.store.UpdateTask(ctx, t.ID, "queued", "", "", "queued", "", s.now())
		if !errors.Is(e, agentgateway.ErrOffline) {
			return domain.Task{}, e
		}
	}
	s.publish(t.ID, "task.updated")
	return s.store.TaskByID(ctx, t.ID)
}

func (s *Service) replayTask(ctx context.Context, nodeID, idempotencyKey, actor, taskType string) (domain.Task, bool, error) {
	existing, err := s.store.TaskByIdempotency(ctx, nodeID, idempotencyKey)
	if errors.Is(err, store.ErrNotFound) {
		return domain.Task{}, false, nil
	}
	if err != nil {
		return domain.Task{}, false, err
	}
	if existing.Type != taskType || existing.RequestedBy != actor {
		return domain.Task{}, false, store.ErrConflict
	}
	return existing, true, nil
}

func (s *Service) Cancel(ctx context.Context, id string) (domain.Task, error) {
	return s.CancelAs(ctx, id, "task.cancel", "task/"+id)
}
func (s *Service) CancelAs(ctx context.Context, id, action, resource string) (domain.Task, error) {
	before, e := s.store.TaskByID(ctx, id)
	if e != nil {
		return domain.Task{}, e
	}
	v, e := s.store.CancelTask(store.WithMutationAction(ctx, action, resource), id, s.now().UTC())
	if e != nil {
		return domain.Task{}, e
	}
	if s.gateway != nil && (before.State == "dispatched" || before.State == "running") {
		_ = s.gateway.Cancel(ctx, before.NodeID, id, "cancelled by user")
	}
	s.publish(id, "task.updated")
	metrics.Default.TaskCancelled()
	return v, nil
}

func (s *Service) ExpireOnce(ctx context.Context) (int, error) {
	expired, e := s.store.ExpireTasks(ctx, s.now().UTC(), 100)
	if e != nil {
		return 0, e
	}
	for _, v := range expired {
		if s.gateway != nil {
			_ = s.gateway.Cancel(ctx, v.NodeID, v.ID, "task deadline exceeded")
		}
		if s.alerter != nil {
			kind := "task_timeout"
			if v.Type == "frp_upgrade" {
				kind = "upgrade_timeout"
			}
			s.alerter.Trigger(ctx, kind, "critical", "task/"+v.ID, "task deadline exceeded")
		}
		s.publish(v.ID, "task.updated")
	}
	metrics.Default.TaskTimeout(len(expired))
	return len(expired), nil
}

func (s *Service) RunReaper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	_, _ = s.ExpireOnce(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = s.ExpireOnce(ctx)
		}
	}
}
func (s *Service) publish(id, kind string) {
	if s.events != nil {
		s.events.Publish(events.Event{ID: id, Type: kind, Data: []byte(`{}`)})
	}
}
