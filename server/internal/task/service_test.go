package task

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/events"
	"github.com/frp-admin/frp-admin/server/internal/store"
	"github.com/frp-admin/frp-admin/server/internal/store/sqlstore"
	"github.com/google/uuid"
)

func newCapabilityFixture(t *testing.T) (*sqlstore.Store, string, string) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlstore.Open(ctx, "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	userID, nodeID := uuid.NewString(), uuid.NewString()
	if err = db.CreateUser(ctx, domain.User{ID: userID, Username: "admin-" + userID, PasswordHash: "unused", Status: "active", Role: "admin", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	token := domain.EnrollmentToken{ID: uuid.NewString(), Role: "client", TokenHash: uuid.NewString(), CreatedBy: userID, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err = db.CreateEnrollmentToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err = db.ConsumeEnrollmentTokenAndCreateNode(ctx, token.TokenHash, token.Role, domain.Node{ID: nodeID, Name: "node", Role: "client", Labels: "{}", ManagementMode: "managed", CreatedAt: now, UpdatedAt: now}, now); err != nil {
		t.Fatal(err)
	}
	if err = db.UpsertObservation(ctx, domain.NodeObservation{NodeID: nodeID, Online: true, Capabilities: `[]`, LastHeartbeat: now}); err != nil {
		t.Fatal(err)
	}
	return db, nodeID, userID
}

func TestCapabilityGatesAndIdempotencyReplay(t *testing.T) {
	ctx := context.Background()
	db, nodeID, actor := newCapabilityFixture(t)
	service := New(db, nil, events.New())

	operations := []struct {
		name string
		run  func(string) (domain.Task, error)
	}{
		{"inspect", func(key string) (domain.Task, error) { return service.Inspect(ctx, nodeID, actor, key) }},
		{"risk scan", func(key string) (domain.Task, error) { return service.InspectRisk(ctx, nodeID, actor, key) }},
		{"runtime", func(key string) (domain.Task, error) { return service.CollectRuntime(ctx, nodeID, actor, key) }},
		{"service start", func(key string) (domain.Task, error) { return service.ServiceAction(ctx, nodeID, "start", actor, key) }},
		{"service stop", func(key string) (domain.Task, error) { return service.ServiceAction(ctx, nodeID, "stop", actor, key) }},
		{"service restart", func(key string) (domain.Task, error) {
			return service.ServiceAction(ctx, nodeID, "restart", actor, key)
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			if _, err := operation.run("missing-" + operation.name); !errors.Is(err, store.ErrCapabilityUnavailable) {
				t.Fatalf("got %v, want capability unavailable", err)
			}
		})
	}
	page, err := db.ListTasks(ctx, 10, "", "", nodeID)
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("capability failures created tasks: count=%d err=%v", len(page.Items), err)
	}

	now := time.Now().UTC()
	if err = db.UpsertObservation(ctx, domain.NodeObservation{NodeID: nodeID, Online: true, Capabilities: `["inspect"]`, LastHeartbeat: now}); err != nil {
		t.Fatal(err)
	}
	created, err := service.Inspect(ctx, nodeID, actor, "inspect-replay")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.UpsertObservation(ctx, domain.NodeObservation{NodeID: nodeID, Online: true, Capabilities: `[]`, LastHeartbeat: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	replayed, err := service.Inspect(ctx, nodeID, actor, "inspect-replay")
	if err != nil || replayed.ID != created.ID {
		t.Fatalf("replay after capability removal: id=%s err=%v", replayed.ID, err)
	}
	if _, err = service.Inspect(ctx, nodeID, "different-actor", "inspect-replay"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("same key with different actor got %v", err)
	}
	if _, err = service.CollectRuntime(ctx, nodeID, actor, "inspect-replay"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("same key with different task type got %v", err)
	}
}
