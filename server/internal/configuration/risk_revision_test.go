package configuration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/configcrypto"
	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/events"
	"github.com/frp-admin/frp-admin/server/internal/store/sqlstore"
	"github.com/google/uuid"
	"github.com/pelletier/go-toml/v2"
)

func TestCreateAdminLoopbackRevisionRequiresInSyncDesiredConfig(t *testing.T) {
	ctx := context.Background()
	db, err := sqlstore.Open(ctx, "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	userID, nodeID := uuid.NewString(), uuid.NewString()
	if err = db.CreateUser(ctx, domain.User{ID: userID, Username: "admin", PasswordHash: "x", Status: "active", Role: "admin", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	token := domain.EnrollmentToken{ID: uuid.NewString(), Role: "server", TokenHash: uuid.NewString(), CreatedBy: userID, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err = db.CreateEnrollmentToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err = db.ConsumeEnrollmentTokenAndCreateNode(ctx, token.TokenHash, token.Role, domain.Node{ID: nodeID, Name: "frps", Role: "server", Labels: "{}", ManagementMode: "managed", CreatedAt: now, UpdatedAt: now}, now); err != nil {
		t.Fatal(err)
	}
	cipher, err := configcrypto.LoadOrCreate(t.TempDir() + "/master.key")
	if err != nil {
		t.Fatal(err)
	}
	service := New(db, cipher, events.New())
	base, err := service.Create(ctx, nodeID, userID, "restart", []byte("# operator note\nbindPort = 7000\n[webServer] # dashboard\naddr = \"0.0.0.0\" # public before repair\nport = 7500\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err = db.UpsertObservation(ctx, domain.NodeObservation{NodeID: nodeID, Online: true, LastHeartbeat: now}); err != nil {
		t.Fatal(err)
	}
	task := domain.Task{ID: uuid.NewString(), Type: "config_apply", State: "running", NodeID: nodeID, IdempotencyKey: uuid.NewString(), RequestedBy: userID, ConfigRevisionID: &base.ID, CreatedAt: now, UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.NewString(), TaskID: task.ID, Name: "config_apply", State: "running", Attempt: 1, CreatedAt: now, UpdatedAt: now}
	if err = db.CreateTask(ctx, task, step); err != nil {
		t.Fatal(err)
	}
	if _, err = db.CompleteConfigTask(ctx, task, "succeeded", "", "", "", "base-material-sha", now); err != nil {
		t.Fatal(err)
	}
	completedNode := mustNode(t, db, ctx, nodeID)
	if completedNode.Observation == nil || completedNode.Observation.ObservedRevisionID == nil || *completedNode.Observation.ObservedRevisionID != base.ID || completedNode.Observation.ObservedHash != "base-material-sha" {
		t.Fatalf("completion did not persist observed revision proof: %+v", completedNode.Observation)
	}
	derived, err := service.CreateAdminLoopbackRevision(ctx, nodeID, userID)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := service.Content(ctx, derived.ID)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = toml.Unmarshal([]byte(plain.Content), &document); err != nil {
		t.Fatal(err)
	}
	web := document["webServer"].(map[string]any)
	if web["addr"] != "127.0.0.1" || derived.Strategy != "restart" {
		t.Fatalf("derived revision=%+v webServer=%v", derived, web)
	}
	if !strings.Contains(plain.Content, "# operator note") || !strings.Contains(plain.Content, "# public before repair") || !strings.Contains(plain.Content, "[webServer] # dashboard") {
		t.Fatalf("derived revision lost formatting/comments: %s", plain.Content)
	}
	newer, err := service.Create(ctx, nodeID, userID, "restart", []byte("bindPort = 7000\n[webServer]\naddr = \"127.0.0.1\"\nport = 7500\n"))
	if err != nil {
		t.Fatal(err)
	}
	advance := domain.Task{ID: uuid.NewString(), Type: "config_apply", State: "running", NodeID: nodeID, IdempotencyKey: uuid.NewString(), RequestedBy: userID, ConfigRevisionID: &newer.ID, ExpectedRevisionID: &base.ID, CreatedAt: now, UpdatedAt: now}
	if err = db.CreateTask(ctx, advance, domain.TaskStep{ID: uuid.NewString(), TaskID: advance.ID, Name: "config_apply", State: "running", Attempt: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if final, completeErr := db.CompleteConfigTask(ctx, advance, "succeeded", "", "", "", "newer-sha", now); completeErr != nil || final.FinalState != "succeeded" {
		t.Fatalf("advance desired final=%+v err=%v", final, completeErr)
	}
	stale := domain.Task{ID: uuid.NewString(), Type: "risk_repair", State: "running", NodeID: nodeID, IdempotencyKey: uuid.NewString(), RequestedBy: userID, ConfigRevisionID: &derived.ID, ExpectedRevisionID: &base.ID, CreatedAt: now, UpdatedAt: now}
	if err = db.CreateTask(ctx, stale, domain.TaskStep{ID: uuid.NewString(), TaskID: stale.ID, Name: "risk_repair", State: "running", Attempt: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if final, completeErr := db.CompleteConfigTask(ctx, stale, "succeeded", "", "", "{}", "stale-sha", now); completeErr != nil || final.FinalState != "failed" || !final.AppliedDrift {
		t.Fatalf("stale desired CAS final=%+v err=%v", final, completeErr)
	}
	driftedNode := mustNode(t, db, ctx, nodeID)
	if driftedNode.DesiredRevisionID == nil || *driftedNode.DesiredRevisionID != newer.ID || driftedNode.Observation == nil || driftedNode.Observation.ObservedRevisionID == nil || *driftedNode.Observation.ObservedRevisionID != derived.ID || driftedNode.Observation.ObservedHash != "stale-sha" {
		t.Fatalf("applied proof was not retained after desired CAS failure: %+v", driftedNode)
	}
	staleRecord, err := db.TaskByID(ctx, stale.ID)
	if err != nil || staleRecord.State != "failed" || staleRecord.ErrorCode != "PRECONDITION_FAILED" {
		t.Fatalf("stale task=%+v err=%v", staleRecord, err)
	}
	audits, err := db.ListAuditLogs(ctx, domain.AuditFilter{Action: "deployment_risk.repair.result"}, 10, "")
	if err != nil || len(audits.Items) != 1 || audits.Items[0].RequestID != stale.ID || audits.Items[0].Outcome != "applied_drift" {
		t.Fatalf("atomic repair result audit=%+v err=%v", audits.Items, err)
	}

	observation := *mustNode(t, db, ctx, nodeID).Observation
	observation.ObservedRevisionID = nil
	if err = db.UpsertObservation(ctx, observation); err != nil {
		t.Fatal(err)
	}
	if _, err = service.CreateAdminLoopbackRevision(ctx, nodeID, userID); !errors.Is(err, ErrDesiredRevisionDrift) {
		t.Fatalf("drifted node accepted: %v", err)
	}
}

func mustNode(t *testing.T, db *sqlstore.Store, ctx context.Context, id string) domain.Node {
	t.Helper()
	node, err := db.NodeByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return node
}
