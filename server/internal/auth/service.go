package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/store"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrBootstrapDisabled  = errors.New("bootstrap is disabled")
	ErrForbidden          = errors.New("forbidden")
)

type Service struct {
	store          store.Store
	bootstrapToken string
	sessionTTL     time.Duration
	now            func() time.Time
}
type Credentials struct{ Username, Password string }
type Tokens struct {
	SessionToken, CSRFToken string
	ExpiresAt               time.Time
}

func New(s store.Store, bootstrapToken string, ttl time.Duration) *Service {
	return &Service{store: s, bootstrapToken: bootstrapToken, sessionTTL: ttl, now: time.Now}
}

func (s *Service) NeedsBootstrap(ctx context.Context) (bool, error) {
	n, e := s.store.CountUsers(ctx)
	return n == 0, e
}
func (s *Service) Bootstrap(ctx context.Context, token string, c Credentials) (domain.User, error) {
	need, e := s.NeedsBootstrap(ctx)
	if e != nil {
		return domain.User{}, e
	}
	if !need {
		return domain.User{}, ErrBootstrapDisabled
	}
	if s.bootstrapToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.bootstrapToken)) != 1 {
		return domain.User{}, ErrInvalidCredentials
	}
	return s.createUser(ctx, c, "admin")
}
func (s *Service) createUser(ctx context.Context, c Credentials, role string) (domain.User, error) {
	name := strings.TrimSpace(c.Username)
	if len(name) < 3 || len(name) > 128 {
		return domain.User{}, fmt.Errorf("username must contain 3-128 characters")
	}
	if len(c.Password) < 12 {
		return domain.User{}, fmt.Errorf("password must contain at least 12 characters")
	}
	h, e := hashPassword(c.Password)
	if e != nil {
		return domain.User{}, e
	}
	u := domain.User{ID: uuid.Must(uuid.NewV7()).String(), Username: name, PasswordHash: h, Status: "active", Role: role, CreatedAt: s.now().UTC()}
	if _, ok := store.MutationAuditFrom(ctx); ok {
		ctx = store.WithMutationAction(ctx, "user.create", "user/"+u.ID)
	}
	if e = s.store.CreateUser(ctx, u); e != nil {
		return domain.User{}, e
	}
	u.PasswordHash = ""
	return u, nil
}
func (s *Service) CreateUser(ctx context.Context, c Credentials, role string) (domain.User, error) {
	if !Allowed(role, "admin", "operator", "viewer", "auditor") {
		return domain.User{}, errors.New("invalid role")
	}
	return s.createUser(ctx, c, role)
}
func (s *Service) ListUsers(ctx context.Context, limit int, cursor string) (domain.Page[domain.User], error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	return s.store.ListUsers(ctx, limit, cursor)
}
func (s *Service) UpdateUser(ctx context.Context, id, statusValue, role string) error {
	if statusValue != "" && statusValue != "active" && statusValue != "disabled" {
		return errors.New("invalid user status")
	}
	if role != "" && !Allowed(role, "admin", "operator", "viewer", "auditor") {
		return errors.New("invalid role")
	}
	return s.store.UpdateUserAccess(store.WithMutationAction(ctx, "user.update", "user/"+id), id, statusValue, role, s.now().UTC())
}
func (s *Service) UpdateProfile(ctx context.Context, userID, displayName string) (domain.User, error) {
	if len(strings.TrimSpace(displayName)) > 128 {
		return domain.User{}, errors.New("display name must be at most 128 characters")
	}
	ctx = store.WithMutationAction(ctx, "user.profile.update", "user/"+userID)
	if err := s.store.UpdateUserProfile(ctx, userID, displayName); err != nil {
		return domain.User{}, err
	}
	u, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return domain.User{}, err
	}
	u.PasswordHash = ""
	return u, nil
}

func (s *Service) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	if len(newPassword) < 12 {
		return errors.New("password must contain at least 12 characters")
	}
	u, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !verifyPassword(currentPassword, u.PasswordHash) {
		return ErrInvalidCredentials
	}
	h, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	ctx = store.WithMutationAction(ctx, "user.password.change", "user/"+userID)
	return s.store.UpdateUserPassword(ctx, userID, h, s.now().UTC())
}

func (s *Service) Login(ctx context.Context, c Credentials) (domain.User, Tokens, error) {
	u, e := s.store.UserByUsername(ctx, strings.TrimSpace(c.Username))
	if e != nil || u.Status != "active" || !verifyPassword(c.Password, u.PasswordHash) {
		return domain.User{}, Tokens{}, ErrInvalidCredentials
	}
	tokens, e := s.newSession(ctx, u.ID)
	if e != nil {
		return domain.User{}, Tokens{}, e
	}
	u.PasswordHash = ""
	return u, tokens, nil
}
func (s *Service) newSession(ctx context.Context, userID string) (Tokens, error) {
	raw, e := randomToken()
	if e != nil {
		return Tokens{}, e
	}
	csrf, e := randomToken()
	if e != nil {
		return Tokens{}, e
	}
	ex := s.now().UTC().Add(s.sessionTTL)
	v := domain.Session{ID: uuid.Must(uuid.NewV7()).String(), UserID: userID, TokenHash: digest(raw), CSRFHash: digest(csrf), ExpiresAt: ex}
	if e = s.store.CreateSession(ctx, v); e != nil {
		return Tokens{}, e
	}
	return Tokens{SessionToken: raw, CSRFToken: csrf, ExpiresAt: ex}, nil
}
func (s *Service) Authenticate(ctx context.Context, token string) (domain.User, domain.Session, error) {
	if token == "" {
		return domain.User{}, domain.Session{}, ErrInvalidCredentials
	}
	sess, e := s.store.SessionByTokenHash(ctx, digest(token), s.now())
	if e != nil {
		return domain.User{}, domain.Session{}, ErrInvalidCredentials
	}
	u, e := s.store.UserByID(ctx, sess.UserID)
	if e != nil || u.Status != "active" {
		return domain.User{}, domain.Session{}, ErrInvalidCredentials
	}
	u.PasswordHash = ""
	return u, sess, nil
}
func (s *Service) Logout(ctx context.Context, id string) error {
	return s.store.RevokeSession(ctx, id, s.now())
}
func VerifyCSRF(session domain.Session, token string) bool {
	return token != "" && subtle.ConstantTimeCompare([]byte(session.CSRFHash), []byte(digest(token))) == 1
}
func Allowed(role string, allowed ...string) bool {
	for _, v := range allowed {
		if role == v {
			return true
		}
	}
	return false
}
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func digest(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	h := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=2$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(h)), nil
}
func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	var memory, iterations uint64
	var parallelism uint64
	for _, p := range strings.Split(parts[3], ",") {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			return false
		}
		v, e := strconv.ParseUint(kv[1], 10, 32)
		if e != nil {
			return false
		}
		switch kv[0] {
		case "m":
			memory = v
		case "t":
			iterations = v
		case "p":
			parallelism = v
		default:
			return false
		}
	}
	if memory == 0 || iterations == 0 || parallelism == 0 || parallelism > 255 {
		return false
	}
	salt, e := base64.RawStdEncoding.DecodeString(parts[4])
	if e != nil {
		return false
	}
	expected, e := base64.RawStdEncoding.DecodeString(parts[5])
	if e != nil || len(expected) == 0 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, uint32(iterations), uint32(memory), uint8(parallelism), uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func GenerateBootstrapToken() (string, error) { return randomToken() }
