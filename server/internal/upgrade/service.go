package upgrade

import (
	"context"
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/agentcap"
	"github.com/frp-admin/frp-admin/server/internal/agentgateway"
	"github.com/frp-admin/frp-admin/server/internal/configcrypto"
	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/events"
	"github.com/frp-admin/frp-admin/server/internal/store"
	"github.com/frp-admin/frp-admin/server/internal/task"
	"github.com/google/uuid"
)

var versionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?$`)

type Service struct {
	store   store.Store
	gateway agentgateway.Gateway
	tasks   *task.Service
	events  *events.Bus
	now     func() time.Time
	timeout time.Duration
	cipher  *configcrypto.Cipher
}

type Created struct {
	Plan domain.UpgradePlan
	Task domain.Task
}

func New(s store.Store, gateway agentgateway.Gateway, tasks *task.Service, bus *events.Bus, timeout time.Duration, ciphers ...*configcrypto.Cipher) *Service {
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	v := &Service{store: s, gateway: gateway, tasks: tasks, events: bus, now: time.Now, timeout: timeout}
	if len(ciphers) > 0 {
		v.cipher = ciphers[0]
	}
	return v
}

func (s *Service) Create(ctx context.Context, nodeID, version, artifactURL, sha256, actor, idempotency string) (Created, error) {
	version = strings.TrimSpace(version)
	if !versionPattern.MatchString(version) {
		return Created{}, errors.New("invalid target version")
	}
	artifactURL = strings.TrimSpace(artifactURL)
	parsed, err := url.Parse(artifactURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || len(artifactURL) > 2048 {
		return Created{}, errors.New("artifact_url must be an absolute HTTPS URL without credentials or fragment")
	}
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	decoded, err := hex.DecodeString(sha256)
	if err != nil || len(decoded) != 32 {
		return Created{}, errors.New("sha256 must contain exactly 64 hexadecimal characters")
	}
	idempotency = strings.TrimSpace(idempotency)
	if idempotency == "" || len(idempotency) > 255 {
		return Created{}, errors.New("Idempotency-Key is required and must not exceed 255 characters")
	}
	if existing, found, err := s.replay(ctx, nodeID, version, artifactURL, sha256, actor, idempotency); err != nil || found {
		return existing, err
	}
	node, err := s.store.NodeByID(ctx, nodeID)
	if err != nil {
		return Created{}, err
	}
	if node.ManagementMode != "managed" {
		return Created{}, store.ErrObserveOnly
	}
	if !agentcap.Has(node, "frp.upgrade") {
		return Created{}, store.ErrCapabilityUnavailable
	}
	now := s.now().UTC()
	expires := now.Add(s.timeout)
	planID, taskID := uuid.Must(uuid.NewV7()).String(), uuid.Must(uuid.NewV7()).String()
	if s.cipher == nil {
		return Created{}, errors.New("upgrade artifact encryption is unavailable")
	}
	ciphertext, nonce, keyVersion, err := s.cipher.SealSecret("upgrade-artifact/"+planID, []byte(artifactURL))
	if err != nil {
		return Created{}, errors.New("encrypt upgrade artifact URL")
	}
	plan := domain.UpgradePlan{ID: planID, NodeID: nodeID, Version: version, ArtifactCiphertext: ciphertext, ArtifactNonce: nonce, ArtifactKeyVersion: keyVersion, SHA256: sha256, State: "queued", TaskID: taskID, CreatedBy: actor, CreatedAt: now, UpdatedAt: now}
	taskRecord := domain.Task{ID: taskID, Type: "frp_upgrade", State: "queued", NodeID: nodeID, IdempotencyKey: idempotency, RequestedBy: actor, Payload: "{}", UpgradePlanID: &planID, ExpiresAt: &expires, CreatedAt: now, UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.Must(uuid.NewV7()).String(), TaskID: taskID, Name: "frp_upgrade", State: "queued", Attempt: 1, CreatedAt: now, UpdatedAt: now}
	if err = s.store.CreateUpgradePlanTask(store.WithMutationAction(ctx, "upgrade_plan.create", "upgrade_plan/"+planID), plan, taskRecord, step); err != nil {
		if errors.Is(err, store.ErrConflict) {
			if existing, found, replayErr := s.replay(ctx, nodeID, version, artifactURL, sha256, actor, idempotency); replayErr != nil || found {
				return existing, replayErr
			}
		}
		return Created{}, err
	}
	s.publish(taskID, "task.created")
	if s.gateway != nil && s.gateway.Connected(nodeID) {
		if err = s.store.UpdateTask(ctx, taskID, "dispatched", "", "", "dispatched", "", now); err != nil {
			return Created{}, err
		}
		command := agentgateway.Command{ID: taskID, NodeID: nodeID, Type: "frp_upgrade", Version: version, ArtifactURL: artifactURL, SHA256: sha256, ExpiresAt: expires}
		if err = s.gateway.Dispatch(ctx, command); err != nil {
			_ = s.store.UpdateTask(ctx, taskID, "queued", "", "", "queued", "", s.now().UTC())
			if !errors.Is(err, agentgateway.ErrOffline) {
				return Created{}, err
			}
		}
		s.publish(taskID, "task.updated")
	}
	plan, err = s.store.UpgradePlanByID(ctx, planID)
	if err != nil {
		return Created{}, err
	}
	if err = s.decryptArtifactURL(&plan); err != nil {
		return Created{}, err
	}
	taskRecord, err = s.store.TaskByID(ctx, taskID)
	return Created{Plan: plan, Task: taskRecord}, err
}

func (s *Service) replay(ctx context.Context, nodeID, version, artifactURL, sha256, actor, idempotency string) (Created, bool, error) {
	taskRecord, err := s.store.TaskByIdempotency(ctx, nodeID, idempotency)
	if errors.Is(err, store.ErrNotFound) {
		return Created{}, false, nil
	}
	if err != nil {
		return Created{}, false, err
	}
	if taskRecord.Type != "frp_upgrade" || taskRecord.RequestedBy != actor || taskRecord.UpgradePlanID == nil {
		return Created{}, false, store.ErrConflict
	}
	plan, err := s.store.UpgradePlanByID(ctx, *taskRecord.UpgradePlanID)
	if err != nil {
		return Created{}, false, err
	}
	if err = s.decryptArtifactURL(&plan); err != nil {
		return Created{}, false, err
	}
	if plan.NodeID != nodeID || plan.Version != version || plan.SHA256 != sha256 || plan.ArtifactURL != artifactURL {
		return Created{}, false, store.ErrConflict
	}
	return Created{Plan: plan, Task: taskRecord}, true, nil
}

func (s *Service) Get(ctx context.Context, id string) (domain.UpgradePlan, domain.Task, error) {
	v, err := s.store.UpgradePlanByID(ctx, id)
	if err != nil {
		return v, domain.Task{}, err
	}
	if err = s.decryptArtifactURL(&v); err != nil {
		return v, domain.Task{}, err
	}
	t, err := s.store.TaskByID(ctx, v.TaskID)
	return v, t, err
}
func (s *Service) List(ctx context.Context, limit int, cursor, nodeID, state string) (domain.Page[domain.UpgradePlan], error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if state != "" && state != "queued" && state != "running" && state != "succeeded" && state != "failed" && state != "cancelled" {
		return domain.Page[domain.UpgradePlan]{}, errors.New("invalid upgrade state")
	}
	page, err := s.store.ListUpgradePlans(ctx, limit, cursor, nodeID, state)
	if err != nil {
		return page, err
	}
	for i := range page.Items {
		if err = s.decryptArtifactURL(&page.Items[i]); err != nil {
			return domain.Page[domain.UpgradePlan]{}, err
		}
	}
	return page, nil
}
func (s *Service) Cancel(ctx context.Context, id string) (domain.UpgradePlan, domain.Task, error) {
	v, err := s.store.UpgradePlanByID(ctx, id)
	if err != nil {
		return v, domain.Task{}, err
	}
	t, err := s.tasks.CancelAs(ctx, v.TaskID, "upgrade_plan.cancel", "upgrade_plan/"+id)
	if err != nil {
		return v, domain.Task{}, err
	}
	v, err = s.store.UpgradePlanByID(ctx, id)
	if err == nil {
		err = s.decryptArtifactURL(&v)
	}
	return v, t, err
}

func (s *Service) MaterializeUpgrade(ctx context.Context, id string) (agentgateway.UpgradeMaterial, error) {
	v, err := s.store.UpgradePlanByID(ctx, id)
	if err != nil {
		return agentgateway.UpgradeMaterial{}, err
	}
	if err = s.decryptArtifactURL(&v); err != nil {
		return agentgateway.UpgradeMaterial{}, err
	}
	return agentgateway.UpgradeMaterial{Version: v.Version, ArtifactURL: v.ArtifactURL, SHA256: v.SHA256}, nil
}

func (s *Service) decryptArtifactURL(v *domain.UpgradePlan) error {
	if s.cipher == nil {
		return errors.New("upgrade artifact encryption is unavailable")
	}
	plaintext, err := s.cipher.OpenSecret("upgrade-artifact/"+v.ID, v.ArtifactKeyVersion, v.ArtifactCiphertext, v.ArtifactNonce)
	if err != nil {
		return errors.New("decrypt upgrade artifact URL")
	}
	v.ArtifactURL = string(plaintext)
	return nil
}
func (s *Service) publish(id, kind string) {
	if s.events != nil {
		s.events.Publish(events.Event{ID: id, Type: kind, Data: []byte(`{}`)})
	}
}
