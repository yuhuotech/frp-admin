package configuration

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/configcrypto"
	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/events"
	"github.com/frp-admin/frp-admin/server/internal/store"
	"github.com/frp-admin/frp-admin/server/internal/store/sqlstore"
	"github.com/google/uuid"
)

func TestConfigTaskCapabilityGatesAndReplay(t *testing.T) {
	ctx := context.Background()
	db, err := sqlstore.Open(ctx, "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	actor, nodeID := uuid.NewString(), uuid.NewString()
	if err = db.CreateUser(ctx, domain.User{ID: actor, Username: "admin-" + actor, PasswordHash: "unused", Status: "active", Role: "admin", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	token := domain.EnrollmentToken{ID: uuid.NewString(), Role: "client", TokenHash: uuid.NewString(), CreatedBy: actor, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err = db.CreateEnrollmentToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err = db.ConsumeEnrollmentTokenAndCreateNode(ctx, token.TokenHash, token.Role, domain.Node{ID: nodeID, Name: "node", Role: "client", Labels: "{}", ManagementMode: "managed", CreatedAt: now, UpdatedAt: now}, now); err != nil {
		t.Fatal(err)
	}
	if err = db.UpsertObservation(ctx, domain.NodeObservation{NodeID: nodeID, Online: true, Capabilities: `[]`, LastHeartbeat: now}); err != nil {
		t.Fatal(err)
	}
	cipher, err := configcrypto.LoadOrCreate(filepath.Join(t.TempDir(), "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	service := New(db, cipher, events.New())
	revision, err := service.Create(ctx, nodeID, actor, "restart", []byte("serverAddr = \"example.test\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Deploy(ctx, revision.ID, actor, "deploy-key"); !errors.Is(err, store.ErrCapabilityUnavailable) {
		t.Fatalf("deploy without capability got %v", err)
	}
	page, err := db.ListTasks(ctx, 10, "", "", nodeID)
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("capability failure created a task: count=%d err=%v", len(page.Items), err)
	}
	if err = db.UpsertObservation(ctx, domain.NodeObservation{NodeID: nodeID, Online: true, Capabilities: `["config.apply"]`, LastHeartbeat: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	created, err := service.Deploy(ctx, revision.ID, actor, "deploy-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Rollback(ctx, nodeID, revision.ID, actor, "rollback-key"); !errors.Is(err, store.ErrCapabilityUnavailable) {
		t.Fatalf("rollback without capability got %v", err)
	}
	if err = db.UpsertObservation(ctx, domain.NodeObservation{NodeID: nodeID, Online: true, Capabilities: `[]`, LastHeartbeat: now.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	replayed, err := service.Deploy(ctx, revision.ID, actor, "deploy-key")
	if err != nil || replayed.ID != created.ID {
		t.Fatalf("deploy replay after capability removal: id=%s err=%v", replayed.ID, err)
	}
	if _, err = service.Deploy(ctx, revision.ID, "different-actor", "deploy-key"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("same key with different actor got %v", err)
	}
}
