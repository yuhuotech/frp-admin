package sqlstore_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/store/sqlstore"
	"github.com/google/uuid"
)

func TestDeploymentRiskReconciliationRequiresTwoSuccessfulAbsences(t *testing.T) {
	ctx := context.Background()
	db, err := sqlstore.Open(ctx, "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	userID, nodeID := uuid.NewString(), uuid.NewString()
	if err = db.CreateUser(ctx, domain.User{ID: userID, Username: "risk-admin", PasswordHash: "x", Status: "active", Role: "admin", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	token := domain.EnrollmentToken{ID: uuid.NewString(), Role: "server", TokenHash: "risk-token", CreatedBy: userID, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err = db.CreateEnrollmentToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err = db.ConsumeEnrollmentTokenAndCreateNode(ctx, token.TokenHash, token.Role, domain.Node{ID: nodeID, Name: "server", Role: "server", Labels: "{}", ManagementMode: "managed", CreatedAt: now, UpdatedAt: now}, now); err != nil {
		t.Fatal(err)
	}
	finding := domain.DeploymentRiskObservation{Kind: "admin_api_non_loopback", Severity: "critical", Evidence: "listen=0.0.0.0:7500", Confidence: "high", RuleVersion: "1", ResourceFingerprint: strings.Repeat("a", 64)}
	allRules := []string{"admin_api_non_loopback", "config_token_permissions", "proxy_name_conflict"}
	if err = db.ReconcileDeploymentRisks(ctx, nodeID, "", "pass", "", []domain.DeploymentRiskObservation{finding}, allRules, now); err != nil {
		t.Fatal(err)
	}
	partial := domain.DeploymentRiskObservation{Kind: "config_token_permissions", Severity: "critical", Evidence: "unsafe configuration permissions", Confidence: "high", RuleVersion: "1", ResourceFingerprint: strings.Repeat("b", 64)}
	if err = db.ReconcileDeploymentRisks(ctx, nodeID, "", "fail", "LOG_READ_FAILED", []domain.DeploymentRiskObservation{partial}, []string{"config_token_permissions"}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	page, _ := db.ListDeploymentRisks(ctx, domain.DeploymentRiskFilter{NodeID: nodeID}, 10, "")
	if len(page.Items) != 2 || page.Items[0].State != "open" || page.Items[1].State != "open" {
		t.Fatalf("failed scan changed finding: %+v", page.Items)
	}
	if err = db.ReconcileDeploymentRisks(ctx, nodeID, "", "pass", "", nil, allRules, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	page, _ = db.ListDeploymentRisks(ctx, domain.DeploymentRiskFilter{NodeID: nodeID}, 10, "")
	if page.Items[0].State != "pending_confirmation" {
		t.Fatalf("first absence must be pending: %+v", page.Items[0])
	}
	active, err := db.ListDeploymentRisks(ctx, domain.DeploymentRiskFilter{NodeID: nodeID, State: "active"}, 10, "")
	if err != nil || len(active.Items) != 2 {
		t.Fatalf("active filter omitted pending finding: items=%+v err=%v", active.Items, err)
	}
	if err = db.ReconcileDeploymentRisks(ctx, nodeID, "", "pass", "", nil, allRules, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	page, _ = db.ListDeploymentRisks(ctx, domain.DeploymentRiskFilter{NodeID: nodeID}, 10, "")
	if page.Items[0].State != "resolved" {
		t.Fatalf("second absence must resolve: %+v", page.Items[0])
	}
	if err = db.ReconcileDeploymentRisks(ctx, nodeID, "", "pass", "", []domain.DeploymentRiskObservation{finding}, allRules, now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	page, _ = db.ListDeploymentRisks(ctx, domain.DeploymentRiskFilter{NodeID: nodeID}, 10, "")
	if page.Items[0].State != "open" || page.Items[0].MissedScans != 0 {
		t.Fatalf("seen finding must reopen: %+v", page.Items[0])
	}
}

func TestRiskScanCompletionIsAtomicSerializedAndReplaySafe(t *testing.T) {
	ctx := context.Background()
	db, nodeID, userID, now := deploymentRiskFixture(t)
	finding := domain.DeploymentRiskObservation{Kind: "admin_api_non_loopback", Severity: "critical", Evidence: "redacted", Confidence: "high", RuleVersion: "1", ResourceFingerprint: strings.Repeat("a", 64)}
	if err := db.ReconcileDeploymentRisks(ctx, nodeID, "", "pass", "", []domain.DeploymentRiskObservation{finding}, []string{finding.Kind}, now); err != nil {
		t.Fatal(err)
	}
	tasks := make([]domain.Task, 2)
	for i := range tasks {
		tasks[i] = domain.Task{ID: uuid.NewString(), Type: "risk_scan", State: "dispatched", NodeID: nodeID, IdempotencyKey: uuid.NewString(), RequestedBy: userID, CreatedAt: now, UpdatedAt: now}
		step := domain.TaskStep{ID: uuid.NewString(), TaskID: tasks[i].ID, Name: "risk_scan", State: "dispatched", Attempt: 1, CreatedAt: now, UpdatedAt: now}
		if err := db.CreateTask(ctx, tasks[i], step); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := range tasks {
		go func(index int) {
			<-start
			outcome, err := db.CompleteRiskScanTask(ctx, tasks[index], "succeeded", "", "", "", "pass", "", nil, []string{finding.Kind}, now.Add(time.Duration(index+1)*time.Second))
			if err == nil && (!outcome.Transitioned || outcome.FinalState != "succeeded") {
				err = errors.New("scan completion did not transition")
			}
			results <- err
		}(i)
	}
	close(start)
	for range tasks {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	page, err := db.ListDeploymentRisks(ctx, domain.DeploymentRiskFilter{NodeID: nodeID}, 10, "")
	if err != nil || len(page.Items) != 1 || page.Items[0].State != "resolved" || page.Items[0].MissedScans != 2 {
		t.Fatalf("serialized scans=%+v err=%v", page.Items, err)
	}
	replay, err := db.CompleteRiskScanTask(ctx, tasks[0], "succeeded", "", "", "", "pass", "", nil, []string{finding.Kind}, now.Add(3*time.Second))
	if err != nil || replay.Transitioned {
		t.Fatalf("replay outcome=%+v err=%v", replay, err)
	}
	page, _ = db.ListDeploymentRisks(ctx, domain.DeploymentRiskFilter{NodeID: nodeID}, 10, "")
	if page.Items[0].MissedScans != 2 {
		t.Fatalf("replayed scan advanced absence count: %+v", page.Items[0])
	}
}

func TestLateNonConfigRepairWritesUniqueAppliedAudit(t *testing.T) {
	ctx := context.Background()
	db, nodeID, userID, now := deploymentRiskFixture(t)
	expires := now.Add(-time.Second)
	task := domain.Task{ID: uuid.NewString(), Type: "risk_repair", State: "running", NodeID: nodeID, IdempotencyKey: uuid.NewString(), RequestedBy: userID, Payload: `{}`, ExpiresAt: &expires, CreatedAt: now.Add(-time.Minute), UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.NewString(), TaskID: task.ID, Name: "risk_repair", State: "running", Attempt: 1, CreatedAt: now, UpdatedAt: now}
	if err := db.CreateTask(ctx, task, step); err != nil {
		t.Fatal(err)
	}
	if expired, err := db.ExpireTasks(ctx, now, 10); err != nil || len(expired) != 1 {
		t.Fatalf("expired=%+v err=%v", expired, err)
	}
	outcome, err := db.CompleteConfigTask(ctx, task, "succeeded", "", "", `{"changed":true}`, "", now.Add(time.Second))
	if err != nil || outcome.FinalState != "failed" || !outcome.AppliedDrift || outcome.Transitioned {
		t.Fatalf("late outcome=%+v err=%v", outcome, err)
	}
	replay, err := db.CompleteConfigTask(ctx, task, "succeeded", "", "", `{"changed":true}`, "", now.Add(2*time.Second))
	if err != nil || replay.AppliedDrift {
		t.Fatalf("late replay=%+v err=%v", replay, err)
	}
	audits, err := db.ListAuditLogs(ctx, domain.AuditFilter{Action: "deployment_risk.repair.result"}, 10, "")
	if err != nil || len(audits.Items) != 1 || audits.Items[0].Outcome != "late_applied" {
		t.Fatalf("late audits=%+v err=%v", audits.Items, err)
	}
}

func deploymentRiskFixture(t *testing.T) (*sqlstore.Store, string, string, time.Time) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlstore.Open(ctx, "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	userID, nodeID := uuid.NewString(), uuid.NewString()
	if err = db.CreateUser(ctx, domain.User{ID: userID, Username: "risk-" + uuid.NewString(), PasswordHash: "x", Status: "active", Role: "admin", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	token := domain.EnrollmentToken{ID: uuid.NewString(), Role: "server", TokenHash: uuid.NewString(), CreatedBy: userID, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err = db.CreateEnrollmentToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err = db.ConsumeEnrollmentTokenAndCreateNode(ctx, token.TokenHash, token.Role, domain.Node{ID: nodeID, Name: "server", Role: "server", Labels: "{}", ManagementMode: "managed", CreatedAt: now, UpdatedAt: now}, now); err != nil {
		t.Fatal(err)
	}
	return db, nodeID, userID, now
}
