package secretmgr

import (
	"context"
	"errors"
	"github.com/frp-admin/frp-admin/server/internal/configcrypto"
	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/store"
	"github.com/google/uuid"
	"regexp"
	"time"
)

var namePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,127}$`)

type Service struct {
	store  store.Store
	cipher *configcrypto.Cipher
	now    func() time.Time
}

func New(s store.Store, c *configcrypto.Cipher) *Service {
	return &Service{store: s, cipher: c, now: time.Now}
}
func (s *Service) Create(ctx context.Context, name, value, actor string) (domain.Secret, error) {
	if !namePattern.MatchString(name) {
		return domain.Secret{}, errors.New("invalid secret name")
	}
	if value == "" || len(value) > 64<<10 {
		return domain.Secret{}, errors.New("secret value must contain 1-65536 bytes")
	}
	encrypted, nonce, keyVersion, e := s.cipher.SealSecret(name, []byte(value))
	if e != nil {
		return domain.Secret{}, e
	}
	now := s.now().UTC()
	v := domain.Secret{ID: uuid.Must(uuid.NewV7()).String(), Name: name, Ciphertext: encrypted, Nonce: nonce, KeyVersion: keyVersion, CreatedBy: actor, UpdatedBy: actor, CreatedAt: now, UpdatedAt: now}
	ctx = store.WithMutationAction(ctx, "secret.create", "secret/"+v.ID)
	if e = s.store.CreateSecret(ctx, v); e != nil {
		return domain.Secret{}, e
	}
	v.Ciphertext = nil
	v.Nonce = nil
	return v, nil
}
func (s *Service) Update(ctx context.Context, id, value, actor string) (domain.Secret, error) {
	if value == "" || len(value) > 64<<10 {
		return domain.Secret{}, errors.New("secret value must contain 1-65536 bytes")
	}
	v, e := s.store.SecretByID(ctx, id)
	if e != nil {
		return domain.Secret{}, e
	}
	encrypted, nonce, keyVersion, e := s.cipher.SealSecret(v.Name, []byte(value))
	if e != nil {
		return domain.Secret{}, e
	}
	v.Ciphertext = encrypted
	v.Nonce = nonce
	v.KeyVersion = keyVersion
	v.UpdatedBy = actor
	v.UpdatedAt = s.now().UTC()
	ctx = store.WithMutationAction(ctx, "secret.update", "secret/"+v.ID)
	if e = s.store.UpdateSecret(ctx, v); e != nil {
		return domain.Secret{}, e
	}
	v.Ciphertext = nil
	v.Nonce = nil
	return v, nil
}
func (s *Service) List(ctx context.Context, limit int, cursor string) (domain.Page[domain.Secret], error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	page, e := s.store.ListSecrets(ctx, limit, cursor)
	for i := range page.Items {
		page.Items[i].Ciphertext = nil
		page.Items[i].Nonce = nil
	}
	return page, e
}
func (s *Service) Resolve(ctx context.Context, name string) (string, error) {
	v, e := s.store.SecretByName(ctx, name)
	if e != nil {
		return "", e
	}
	plain, e := s.cipher.OpenSecret(v.Name, v.KeyVersion, v.Ciphertext, v.Nonce)
	if e != nil {
		return "", errors.New("secret decryption failed")
	}
	return string(plain), nil
}
