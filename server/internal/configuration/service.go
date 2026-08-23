package configuration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/agentcap"
	"github.com/frp-admin/frp-admin/server/internal/agentgateway"
	"github.com/frp-admin/frp-admin/server/internal/configcrypto"
	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/events"
	"github.com/frp-admin/frp-admin/server/internal/store"
	"github.com/google/uuid"
	"github.com/pelletier/go-toml/v2"
)

const MaxRawConfigSize = 1 << 20

type SecretResolver interface {
	Resolve(context.Context, string) (string, error)
}
type Service struct {
	store       store.Store
	cipher      *configcrypto.Cipher
	events      *events.Bus
	now         func() time.Time
	mu          sync.RWMutex
	gateway     agentgateway.Gateway
	secrets     SecretResolver
	taskTimeout time.Duration
}

func New(s store.Store, c *configcrypto.Cipher, b *events.Bus, resolvers ...SecretResolver) *Service {
	v := &Service{store: s, cipher: c, events: b, now: time.Now, taskTimeout: 5 * time.Minute}
	if len(resolvers) > 0 {
		v.secrets = resolvers[0]
	}
	return v
}
func (s *Service) SetTaskTimeout(v time.Duration) {
	if v > 0 {
		s.taskTimeout = v
	}
}
func (s *Service) SetGateway(g agentgateway.Gateway) { s.mu.Lock(); s.gateway = g; s.mu.Unlock() }
func (s *Service) Create(ctx context.Context, nodeID, actor, strategy string, content []byte) (domain.ConfigRevision, error) {
	if len(content) == 0 || len(content) > MaxRawConfigSize {
		return domain.ConfigRevision{}, fmt.Errorf("raw TOML must contain 1-%d bytes", MaxRawConfigSize)
	}
	var document map[string]any
	if e := toml.Unmarshal(content, &document); e != nil {
		return domain.ConfigRevision{}, fmt.Errorf("invalid TOML: %w", e)
	}
	fields := sensitivePaths(document, "", nil)
	fieldsJSON, _ := json.Marshal(fields)
	node, e := s.store.NodeByID(ctx, nodeID)
	if e != nil {
		return domain.ConfigRevision{}, e
	}
	if node.ManagementMode != "managed" {
		return domain.ConfigRevision{}, store.ErrObserveOnly
	}
	if strategy == "" {
		strategy = "restart"
	}
	if strategy != "restart" && strategy != "reload" {
		return domain.ConfigRevision{}, errors.New("strategy must be restart or reload")
	}
	if strategy == "reload" && node.Role != "client" {
		return domain.ConfigRevision{}, errors.New("reload strategy is only supported for client nodes")
	}
	for attempt := 0; attempt < 5; attempt++ {
		version, e := s.store.NextConfigVersion(ctx, nodeID)
		if e != nil {
			return domain.ConfigRevision{}, e
		}
		encrypted, nonce, sha, e := s.cipher.Seal(nodeID, version, content)
		if e != nil {
			return domain.ConfigRevision{}, e
		}
		now := s.now().UTC()
		v := domain.ConfigRevision{ID: uuid.Must(uuid.NewV7()).String(), NodeID: nodeID, Version: version, EncryptedContent: encrypted, Nonce: nonce, SHA256: sha, Strategy: strategy, CreatedBy: actor, CreatedAt: now, Mode: "raw", SensitiveFields: string(fieldsJSON)}
		if e = s.store.CreateConfigRevision(store.WithMutationAction(ctx, "config_revision.create", "config_revision/"+v.ID), v); e == nil {
			s.publish(v.ID, "config-revision.created")
			v.Content = string(content)
			v.EncryptedContent = nil
			v.Nonce = nil
			return v, nil
		} else if !errors.Is(e, store.ErrConflict) {
			return domain.ConfigRevision{}, e
		}
	}
	return domain.ConfigRevision{}, store.ErrConflict
}
func (s *Service) List(ctx context.Context, nodeID string, limit int, cursor string) (domain.Page[domain.ConfigRevision], error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	page, e := s.store.ListConfigRevisions(ctx, nodeID, limit, cursor)
	if e != nil {
		return page, e
	}
	for i := range page.Items {
		page.Items[i].EncryptedContent = nil
		page.Items[i].Nonce = nil
	}
	return page, e
}
func (s *Service) Content(ctx context.Context, id string) (domain.ConfigRevision, error) {
	v, e := s.store.ConfigRevisionByID(ctx, id)
	if e != nil {
		return domain.ConfigRevision{}, e
	}
	plain, e := s.cipher.Open(v.NodeID, v.Version, v.EncryptedContent, v.Nonce)
	if e != nil {
		return domain.ConfigRevision{}, errors.New("configuration decryption failed")
	}
	v.Content = string(plain)
	v.EncryptedContent = nil
	v.Nonce = nil
	return v, nil
}

// CreateAdminLoopbackRevision derives an immutable desired revision. It is
// intentionally unavailable when the node is drifted because an automated
// repair must not replace unknown local changes.
func (s *Service) CreateAdminLoopbackRevision(ctx context.Context, nodeID, actor string) (domain.ConfigRevision, error) {
	revision, _, err := s.PrepareAdminLoopbackRevision(ctx, nodeID, actor)
	if err != nil {
		return domain.ConfigRevision{}, err
	}
	if err = s.store.CreateConfigRevision(store.WithMutationAction(ctx, "config_revision.create", "config_revision/"+revision.ID), revision); err != nil {
		return domain.ConfigRevision{}, err
	}
	plain, err := s.cipher.Open(revision.NodeID, revision.Version, revision.EncryptedContent, revision.Nonce)
	if err != nil {
		return domain.ConfigRevision{}, errors.New("configuration decryption failed")
	}
	revision.Content = string(plain)
	revision.EncryptedContent, revision.Nonce = nil, nil
	return revision, nil
}

func (s *Service) PrepareAdminLoopbackRevision(ctx context.Context, nodeID, actor string) (domain.ConfigRevision, agentgateway.ConfigMaterial, error) {
	node, err := s.store.NodeByID(ctx, nodeID)
	if err != nil {
		return domain.ConfigRevision{}, agentgateway.ConfigMaterial{}, err
	}
	if node.Role != "server" || node.ManagementMode != "managed" || node.DesiredRevisionID == nil {
		return domain.ConfigRevision{}, agentgateway.ConfigMaterial{}, store.ErrConflict
	}
	if node.Observation == nil || node.Observation.ObservedRevisionID == nil || *node.Observation.ObservedRevisionID != *node.DesiredRevisionID {
		return domain.ConfigRevision{}, agentgateway.ConfigMaterial{}, ErrDesiredRevisionDrift
	}
	base, err := s.Content(ctx, *node.DesiredRevisionID)
	if err != nil {
		return domain.ConfigRevision{}, agentgateway.ConfigMaterial{}, err
	}
	var document map[string]any
	if err = toml.Unmarshal([]byte(base.Content), &document); err != nil {
		return domain.ConfigRevision{}, agentgateway.ConfigMaterial{}, errors.New("desired configuration is invalid")
	}
	web, ok := document["webServer"].(map[string]any)
	if !ok || positiveInt(web["port"]) == 0 {
		return domain.ConfigRevision{}, agentgateway.ConfigMaterial{}, errors.New("desired configuration has no enabled webServer")
	}
	web["addr"] = "127.0.0.1"
	content, err := patchWebServerAddr([]byte(base.Content), document)
	if err != nil {
		return domain.ConfigRevision{}, agentgateway.ConfigMaterial{}, err
	}
	fieldsJSON, _ := json.Marshal(sensitivePaths(document, "", nil))
	version, err := s.store.NextConfigVersion(ctx, nodeID)
	if err != nil {
		return domain.ConfigRevision{}, agentgateway.ConfigMaterial{}, err
	}
	encrypted, nonce, rawSHA, err := s.cipher.Seal(nodeID, version, content)
	if err != nil {
		return domain.ConfigRevision{}, agentgateway.ConfigMaterial{}, err
	}
	revision := domain.ConfigRevision{ID: uuid.Must(uuid.NewV7()).String(), NodeID: nodeID, Version: version, EncryptedContent: encrypted, Nonce: nonce, SHA256: rawSHA, Strategy: "restart", CreatedBy: actor, CreatedAt: s.now().UTC(), Mode: "raw", SensitiveFields: string(fieldsJSON)}
	materialContent := content
	if s.secrets != nil {
		materialDocument := map[string]any{}
		if err = toml.Unmarshal(content, &materialDocument); err != nil {
			return domain.ConfigRevision{}, agentgateway.ConfigMaterial{}, errors.New("derived configuration is invalid")
		}
		if err = resolveSecrets(ctx, materialDocument, s.secrets); err != nil {
			return domain.ConfigRevision{}, agentgateway.ConfigMaterial{}, err
		}
		if materialContent, err = toml.Marshal(materialDocument); err != nil {
			return domain.ConfigRevision{}, agentgateway.ConfigMaterial{}, errors.New("materialize derived configuration failed")
		}
	}
	sum := sha256.Sum256(materialContent)
	material := agentgateway.ConfigMaterial{NodeID: nodeID, Revision: revision.ID, SHA256: hex.EncodeToString(sum[:]), Strategy: "restart", Content: materialContent}
	return revision, material, nil
}

func positiveInt(value any) int64 {
	switch v := value.(type) {
	case int64:
		if v > 0 {
			return v
		}
	case uint64:
		if v > 0 && v <= uint64(^uint64(0)>>1) {
			return int64(v)
		}
	case int:
		if v > 0 {
			return int64(v)
		}
	}
	return 0
}

var ErrDesiredRevisionDrift = errors.New("desired and observed revisions differ")

var (
	webServerSection = regexp.MustCompile(`(?m)^[ \t]*\[webServer\][ \t]*(?:#.*)?\r?$`)
	nextTOMLSection  = regexp.MustCompile(`(?m)^[ \t]*\[+[^\r\n]+\]+[ \t]*(?:#.*)?\r?$`)
	webServerAddr    = regexp.MustCompile(`(?m)^([ \t]*addr[ \t]*=[ \t]*)("(?:\\.|[^"\\])*"|'[^']*')([ \t]*(?:#.*)?\r?$)`)
)

func patchWebServerAddr(original []byte, expected map[string]any) ([]byte, error) {
	sections := webServerSection.FindAllIndex(original, -1)
	if len(sections) != 1 {
		return nil, errors.New("desired configuration must contain exactly one standard [webServer] section")
	}
	sectionStart := sections[0][0]
	sectionEnd := len(original)
	if next := nextTOMLSection.FindIndex(original[sections[0][1]:]); next != nil {
		sectionEnd = sections[0][1] + next[0]
	}
	body := original[sectionStart:sectionEnd]
	matches := webServerAddr.FindAllSubmatchIndex(body, -1)
	if len(matches) > 1 {
		return nil, errors.New("desired configuration contains duplicate webServer.addr entries")
	}
	var candidate []byte
	if len(matches) == 1 {
		match := matches[0]
		candidate = make([]byte, 0, len(original)+16)
		candidate = append(candidate, original[:sectionStart+match[4]]...)
		candidate = append(candidate, `"127.0.0.1"`...)
		candidate = append(candidate, original[sectionStart+match[5]:]...)
	} else {
		insertAt := sections[0][1]
		lineBreak := "\n"
		if strings.Contains(string(original), "\r\n") {
			lineBreak = "\r\n"
		}
		headerBreak := lineBreak
		if insertAt > 0 && original[insertAt-1] == '\r' {
			headerBreak = "\n"
		}
		for insertAt < len(original) && (original[insertAt] == '\r' || original[insertAt] == '\n') {
			insertAt++
		}
		candidate = make([]byte, 0, len(original)+32)
		candidate = append(candidate, original[:sections[0][1]]...)
		candidate = append(candidate, headerBreak...)
		candidate = append(candidate, `addr = "127.0.0.1"`...)
		if insertAt < len(original) {
			candidate = append(candidate, lineBreak...)
		}
		candidate = append(candidate, original[insertAt:]...)
	}
	var actual map[string]any
	if err := toml.Unmarshal(candidate, &actual); err != nil || !reflect.DeepEqual(actual, expected) {
		return nil, errors.New("derived loopback configuration changed unexpected semantics")
	}
	return candidate, nil
}

func (s *Service) Materialize(ctx context.Context, id string) (agentgateway.ConfigMaterial, error) {
	v, e := s.store.ConfigRevisionByID(ctx, id)
	if e != nil {
		return agentgateway.ConfigMaterial{}, e
	}
	plain, e := s.cipher.Open(v.NodeID, v.Version, v.EncryptedContent, v.Nonce)
	if e != nil {
		return agentgateway.ConfigMaterial{}, errors.New("configuration decryption failed")
	}
	templateSum := sha256.Sum256(plain)
	if hex.EncodeToString(templateSum[:]) != v.SHA256 {
		return agentgateway.ConfigMaterial{}, errors.New("configuration checksum mismatch")
	}
	var document map[string]any
	if e = toml.Unmarshal(plain, &document); e != nil {
		return agentgateway.ConfigMaterial{}, errors.New("stored configuration is invalid")
	}
	if s.secrets != nil {
		if e = resolveSecrets(ctx, document, s.secrets); e != nil {
			return agentgateway.ConfigMaterial{}, e
		}
		plain, e = toml.Marshal(document)
		if e != nil {
			return agentgateway.ConfigMaterial{}, errors.New("materialize configuration failed")
		}
	}
	sum := sha256.Sum256(plain)
	materialSHA := hex.EncodeToString(sum[:])
	return agentgateway.ConfigMaterial{NodeID: v.NodeID, Revision: v.ID, SHA256: materialSHA, Strategy: v.Strategy, Content: plain}, nil
}

var secretRef = regexp.MustCompile(`\$\{secret:([A-Za-z][A-Za-z0-9_.-]{0,127})\}`)

func resolveSecrets(ctx context.Context, v any, resolver SecretResolver) error {
	switch x := v.(type) {
	case map[string]any:
		for k, item := range x {
			if text, ok := item.(string); ok {
				var resolveErr error
				x[k] = secretRef.ReplaceAllStringFunc(text, func(ref string) string {
					name := secretRef.FindStringSubmatch(ref)[1]
					value, e := resolver.Resolve(ctx, name)
					if e != nil {
						resolveErr = errors.New("referenced secret is unavailable")
						return ref
					}
					return value
				})
				if resolveErr != nil {
					return resolveErr
				}
			} else if e := resolveSecrets(ctx, item, resolver); e != nil {
				return e
			}
		}
	case []any:
		for _, item := range x {
			if e := resolveSecrets(ctx, item, resolver); e != nil {
				return e
			}
		}
	}
	return nil
}
func sensitivePaths(v any, prefix string, out []string) []string {
	switch x := v.(type) {
	case map[string]any:
		for key, item := range x {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			lower := strings.ToLower(key)
			if strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") {
				out = append(out, path)
			}
			out = sensitivePaths(item, path, out)
		}
	case []any:
		for _, item := range x {
			out = sensitivePaths(item, prefix, out)
		}
	}
	return out
}
func (s *Service) Deploy(ctx context.Context, revisionID, actor, idempotency string) (domain.Task, error) {
	v, e := s.store.ConfigRevisionByID(ctx, revisionID)
	if e != nil {
		return domain.Task{}, e
	}
	return s.createTask(ctx, "config_apply", v, actor, idempotency)
}
func (s *Service) Rollback(ctx context.Context, nodeID, revisionID, actor, idempotency string) (domain.Task, error) {
	v, e := s.store.ConfigRevisionByID(ctx, revisionID)
	if e != nil {
		return domain.Task{}, e
	}
	if v.NodeID != nodeID {
		return domain.Task{}, store.ErrNotFound
	}
	return s.createTask(ctx, "config_rollback", v, actor, idempotency)
}
func (s *Service) createTask(ctx context.Context, kind string, v domain.ConfigRevision, actor, idempotency string) (domain.Task, error) {
	idempotency = strings.TrimSpace(idempotency)
	if idempotency == "" {
		idempotency = uuid.NewString()
	} else if existing, found, err := s.replayTask(ctx, v.NodeID, idempotency, kind, actor, v.ID); err != nil || found {
		return existing, err
	}
	node, e := s.store.NodeByID(ctx, v.NodeID)
	if e != nil {
		return domain.Task{}, e
	}
	if node.ManagementMode != "managed" {
		return domain.Task{}, store.ErrObserveOnly
	}
	requiredCapability := "config.apply"
	if kind == "config_rollback" {
		requiredCapability = "config.rollback"
	}
	if !agentcap.Has(node, requiredCapability) {
		return domain.Task{}, store.ErrCapabilityUnavailable
	}
	now := s.now().UTC()
	expires := now.Add(s.taskTimeout)
	t := domain.Task{ID: uuid.Must(uuid.NewV7()).String(), Type: kind, State: "queued", NodeID: v.NodeID, IdempotencyKey: idempotency, RequestedBy: actor, Payload: "{}", ConfigRevisionID: &v.ID, ExpectedRevisionID: node.DesiredRevisionID, ExpiresAt: &expires, CreatedAt: now, UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.Must(uuid.NewV7()).String(), TaskID: t.ID, Name: kind, State: "queued", Attempt: 1, CreatedAt: now, UpdatedAt: now}
	if e = s.store.CreateTask(store.WithMutationAction(ctx, "config_revision."+kind, "config_revision/"+v.ID), t, step); e != nil {
		if errors.Is(e, store.ErrConflict) {
			if existing, found, replayErr := s.replayTask(ctx, v.NodeID, idempotency, kind, actor, v.ID); replayErr != nil || found {
				return existing, replayErr
			}
		}
		return domain.Task{}, e
	}
	s.publish(t.ID, "task.created")
	s.mu.RLock()
	gateway := s.gateway
	s.mu.RUnlock()
	if gateway == nil || !gateway.Connected(t.NodeID) {
		return s.store.TaskByID(ctx, t.ID)
	}
	if e = s.store.UpdateTask(ctx, t.ID, "dispatched", "", "", "dispatched", "", s.now()); e != nil {
		return domain.Task{}, e
	}
	material, e := s.Materialize(ctx, v.ID)
	if e != nil {
		return domain.Task{}, e
	}
	command := agentgateway.Command{ID: t.ID, NodeID: t.NodeID, Type: kind, Revision: v.ID, SHA256: material.SHA256, Strategy: material.Strategy, ExpiresAt: expires}
	command.Payload = material.Content
	command.SHA256 = material.SHA256
	command.Strategy = material.Strategy
	if e = gateway.Dispatch(ctx, command); e != nil {
		_ = s.store.UpdateTask(ctx, t.ID, "queued", "", "", "queued", "", s.now())
		if !errors.Is(e, agentgateway.ErrOffline) {
			return domain.Task{}, e
		}
	}
	s.publish(t.ID, "task.updated")
	return s.store.TaskByID(ctx, t.ID)
}

func (s *Service) replayTask(ctx context.Context, nodeID, idempotency, kind, actor, revisionID string) (domain.Task, bool, error) {
	existing, err := s.store.TaskByIdempotency(ctx, nodeID, idempotency)
	if errors.Is(err, store.ErrNotFound) {
		return domain.Task{}, false, nil
	}
	if err != nil {
		return domain.Task{}, false, err
	}
	if existing.Type != kind || existing.RequestedBy != actor || existing.ConfigRevisionID == nil || *existing.ConfigRevisionID != revisionID {
		return domain.Task{}, false, store.ErrConflict
	}
	return existing, true, nil
}

func (s *Service) publish(id, kind string) {
	if s.events != nil {
		s.events.Publish(events.Event{ID: id, Type: kind, Data: []byte(`{}`)})
	}
}
