package node

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/store"
	"github.com/google/uuid"
)

type Service struct {
	store store.Store
	now   func() time.Time
}

func New(s store.Store) *Service { return &Service{store: s, now: time.Now} }
func (s *Service) List(ctx context.Context, limit int, cursor string) (domain.Page[domain.Node], error) {
	return s.store.ListNodes(ctx, clamp(limit), cursor)
}
func (s *Service) Get(ctx context.Context, id string) (domain.Node, error) {
	return s.store.NodeByID(ctx, id)
}
func (s *Service) SetManagementMode(ctx context.Context, id, mode string) (domain.Node, error) {
	if mode != "observe" && mode != "managed" {
		return domain.Node{}, errors.New("management mode must be observe or managed")
	}
	return s.store.SetNodeManagementMode(store.WithMutationAction(ctx, "node.management_mode.update", "node/"+id), id, mode, s.now().UTC())
}
func (s *Service) CreateEnrollmentToken(ctx context.Context, role, actor string, ttl time.Duration) (domain.EnrollmentToken, string, error) {
	if role != "client" && role != "server" {
		return domain.EnrollmentToken{}, "", errors.New("role must be client or server")
	}
	if ttl <= 0 || ttl > time.Hour {
		ttl = 10 * time.Minute
	}
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return domain.EnrollmentToken{}, "", e
	}
	raw := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	v := domain.EnrollmentToken{ID: uuid.Must(uuid.NewV7()).String(), Role: role, TokenHash: hex.EncodeToString(sum[:]), CreatedBy: actor, ExpiresAt: s.now().UTC().Add(ttl), CreatedAt: s.now().UTC()}
	if e := s.store.CreateEnrollmentToken(ctx, v); e != nil {
		return domain.EnrollmentToken{}, "", e
	}
	v.TokenHash = ""
	return v, raw, nil
}
func clamp(v int) int {
	if v <= 0 {
		return 50
	}
	if v > 200 {
		return 200
	}
	return v
}
