package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/store"
	"github.com/frp-admin/frp-admin/server/internal/store/sqlstore"
	"github.com/google/uuid"
)

func TestDatabaseContract(t *testing.T) {
	dialect := os.Getenv("FRP_ADMIN_INTEGRATION_DB_DRIVER")
	dsn := os.Getenv("FRP_ADMIN_INTEGRATION_DB_DSN")
	if dialect == "" || dsn == "" {
		t.Skip("integration database is not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sqlstore.Open(ctx, dialect, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC().Truncate(time.Microsecond)
	suffix := uuid.NewString()
	userID, nodeID := uuid.NewString(), uuid.NewString()
	user := domain.User{ID: userID, Username: "integration-" + suffix, PasswordHash: "hash", Status: "active", Role: "admin", CreatedAt: now}
	if err = db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	loadedUser, err := db.UserByUsername(ctx, user.Username)
	if err != nil || loadedUser.ID != userID || loadedUser.Role != "admin" {
		t.Fatalf("user round trip: user=%+v err=%v", loadedUser, err)
	}

	token := domain.EnrollmentToken{ID: uuid.NewString(), Role: "client", TokenHash: "token-" + suffix, CreatedBy: userID, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err = db.CreateEnrollmentToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	node := domain.Node{ID: nodeID, Name: "node-" + suffix, Role: "client", Labels: "{}", ManagementMode: "managed", CreatedAt: now, UpdatedAt: now}
	if err = db.ConsumeEnrollmentTokenAndCreateNode(ctx, token.TokenHash, token.Role, node, now); err != nil {
		t.Fatal(err)
	}
	modeCtx := store.WithMutationAudit(ctx, store.MutationAudit{Actor: userID, RequestID: "mode-" + suffix})
	if _, err = db.SetNodeManagementMode(store.WithMutationAction(modeCtx, "node.management_mode.update", "node/"+nodeID), nodeID, "observe", now); err != nil {
		t.Fatal(err)
	}
	if changed, changeErr := db.SetNodeManagementMode(store.WithMutationAction(modeCtx, "node.management_mode.update", "node/"+nodeID), nodeID, "managed", now); changeErr != nil || changed.ManagementMode != "managed" {
		t.Fatalf("management mode round trip: node=%+v err=%v", changed, changeErr)
	}

	upgradePlanID, upgradeTaskID := uuid.NewString(), uuid.NewString()
	upgradePlan := domain.UpgradePlan{ID: upgradePlanID, NodeID: nodeID, Version: "v0.70.0", ArtifactCiphertext: []byte("encrypted-url"), ArtifactNonce: []byte("123456789012"), ArtifactKeyVersion: "1", SHA256: strings.Repeat("a", 64), State: "queued", TaskID: upgradeTaskID, CreatedBy: userID, CreatedAt: now, UpdatedAt: now}
	upgradeTask := domain.Task{ID: upgradeTaskID, Type: "frp_upgrade", State: "queued", NodeID: nodeID, IdempotencyKey: "upgrade-" + suffix, RequestedBy: userID, Payload: "{}", UpgradePlanID: &upgradePlanID, CreatedAt: now, UpdatedAt: now}
	upgradeStep := domain.TaskStep{ID: uuid.NewString(), TaskID: upgradeTaskID, Name: "frp_upgrade", State: "queued", Attempt: 1, CreatedAt: now, UpdatedAt: now}
	if err = db.CreateUpgradePlanTask(ctx, upgradePlan, upgradeTask, upgradeStep); err != nil {
		t.Fatal(err)
	}
	loadedPlan, err := db.UpgradePlanByID(ctx, upgradePlanID)
	if err != nil || string(loadedPlan.ArtifactCiphertext) != "encrypted-url" || loadedPlan.ArtifactURL != "" || loadedPlan.ArtifactKeyVersion != "1" {
		t.Fatalf("upgrade plan round trip: plan=%+v err=%v", loadedPlan, err)
	}

	runtime := domain.RuntimeSnapshot{NodeID: nodeID, Role: "client", FRPVersion: "v0.70.0", CollectedAt: now, ProxyCount: 1, ClientCount: 1, Proxies: []domain.RuntimeProxy{{NodeID: nodeID, Name: "ssh", Type: "tcp", Status: "running", LocalAddress: "127.0.0.1:22", RemoteAddress: ":6000", Traffic: domain.RuntimeTraffic{BytesIn: 10, BytesOut: 20}, CollectedAt: now}}, Clients: []domain.RuntimeClient{{ID: "client-1", Address: "10.0.0.1", ConnectedAt: now}}}
	if err = db.ReplaceRuntimeSnapshot(ctx, runtime); err != nil {
		t.Fatal(err)
	}
	loadedRuntime, err := db.RuntimeSnapshotByNode(ctx, nodeID)
	if err != nil || len(loadedRuntime.Proxies) != 1 || len(loadedRuntime.Clients) != 1 || loadedRuntime.Proxies[0].Traffic.BytesOut != 20 {
		t.Fatalf("runtime snapshot round trip: snapshot=%+v err=%v", loadedRuntime, err)
	}
	proxies, err := db.ListRuntimeProxies(ctx, 10, "", nodeID, "running", "tcp")
	if err != nil || len(proxies.Items) != 1 || proxies.Items[0].NodeName != node.Name {
		t.Fatalf("runtime proxy filters: proxies=%+v err=%v", proxies, err)
	}
	stale := runtime
	stale.CollectedAt = now.Add(-time.Minute)
	stale.Proxies = []domain.RuntimeProxy{{NodeID: nodeID, Name: "stale", Type: "udp", Status: "offline", CollectedAt: stale.CollectedAt}}
	if err = db.ReplaceRuntimeSnapshot(ctx, stale); err != nil {
		t.Fatal(err)
	}
	loadedRuntime, err = db.RuntimeSnapshotByNode(ctx, nodeID)
	if err != nil || len(loadedRuntime.Proxies) != 1 || loadedRuntime.Proxies[0].Name != "ssh" {
		t.Fatalf("stale runtime snapshot overwrote current state: snapshot=%+v err=%v", loadedRuntime, err)
	}
	newer := runtime
	newer.CollectedAt = now.Add(time.Second)
	newer.Proxies = []domain.RuntimeProxy{{NodeID: nodeID, Name: "newer", Type: "tcp", Status: "running", CollectedAt: newer.CollectedAt}}
	if err = db.ReplaceRuntimeSnapshot(ctx, newer); err != nil {
		t.Fatal(err)
	}
	loadedRuntime, err = db.RuntimeSnapshotByNode(ctx, nodeID)
	if err != nil || len(loadedRuntime.Proxies) != 1 || loadedRuntime.Proxies[0].Name != "newer" {
		t.Fatalf("newer runtime snapshot did not advance state: snapshot=%+v err=%v", loadedRuntime, err)
	}

	auditCtx := store.WithMutationAudit(ctx, store.MutationAudit{Actor: userID, RequestID: "request-" + suffix})
	secret := domain.Secret{ID: uuid.NewString(), Name: "SECRET_" + suffix, KeyVersion: "1", Ciphertext: []byte("ciphertext"), Nonce: []byte("nonce"), CreatedBy: userID, UpdatedBy: userID, CreatedAt: now, UpdatedAt: now}
	if err = db.CreateSecret(store.WithMutationAction(auditCtx, "secret.create", "secret/"+secret.ID), secret); err != nil {
		t.Fatal(err)
	}
	loadedSecret, err := db.SecretByName(ctx, secret.Name)
	if err != nil || string(loadedSecret.Ciphertext) != "ciphertext" || loadedSecret.KeyVersion != "1" {
		t.Fatalf("secret round trip: secret=%+v err=%v", loadedSecret, err)
	}
	audits, err := db.ListAuditLogs(ctx, domain.AuditFilter{Action: "secret.create"}, 20, "")
	if err != nil || len(audits.Items) == 0 {
		t.Fatalf("transaction audit: items=%d err=%v", len(audits.Items), err)
	}

	revisionID := uuid.NewString()
	revision := domain.ConfigRevision{ID: revisionID, NodeID: nodeID, Version: 1, EncryptedContent: []byte("encrypted"), Nonce: []byte("nonce"), SHA256: "sha256", Strategy: "restart", CreatedBy: userID, CreatedAt: now, Mode: "managed", SensitiveFields: "[]"}
	if err = db.CreateConfigRevision(ctx, revision); err != nil {
		t.Fatal(err)
	}
	loadedRevision, err := db.ConfigRevisionByID(ctx, revisionID)
	if err != nil || loadedRevision.NodeID != nodeID || string(loadedRevision.EncryptedContent) != "encrypted" {
		t.Fatalf("config round trip: revision=%+v err=%v", loadedRevision, err)
	}

	expires := now.Add(-time.Second)
	taskID := uuid.NewString()
	task := domain.Task{ID: taskID, Type: "inspect", State: "queued", NodeID: nodeID, IdempotencyKey: "task-" + suffix, RequestedBy: userID, Payload: "{}", ExpiresAt: &expires, CreatedAt: now, UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.NewString(), TaskID: taskID, Name: "dispatch", State: "queued", Attempt: 0, CreatedAt: now, UpdatedAt: now}
	if err = db.CreateTask(ctx, task, step); err != nil {
		t.Fatal(err)
	}
	expired, err := db.ExpireTasks(ctx, now, 10)
	if err != nil || len(expired) != 1 || expired[0].State != "failed" || expired[0].ErrorCode != "TIMEOUT" {
		t.Fatalf("task expiry: tasks=%+v err=%v", expired, err)
	}

	alert := domain.Alert{ID: uuid.NewString(), Kind: "task_timeout", Severity: "warning", State: "open", Resource: "task/" + taskID, Fingerprint: "fp-" + suffix, Message: "deadline exceeded", CreatedAt: now, UpdatedAt: now}
	if err = db.CreateAlert(ctx, alert); err != nil {
		t.Fatal(err)
	}
	alerts, err := db.ListAlerts(ctx, 10, "", "open")
	if err != nil || len(alerts.Items) == 0 {
		t.Fatalf("alert round trip: alerts=%+v err=%v", alerts, err)
	}

	riskNodeID := uuid.NewString()
	riskToken := domain.EnrollmentToken{ID: uuid.NewString(), Role: "server", TokenHash: "risk-token-" + suffix, CreatedBy: userID, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err = db.CreateEnrollmentToken(ctx, riskToken); err != nil {
		t.Fatal(err)
	}
	if err = db.ConsumeEnrollmentTokenAndCreateNode(ctx, riskToken.TokenHash, riskToken.Role, domain.Node{ID: riskNodeID, Name: "risk-" + suffix, Role: "server", Labels: "{}", ManagementMode: "managed", CreatedAt: now, UpdatedAt: now}, now); err != nil {
		t.Fatal(err)
	}
	if err = db.UpsertObservation(ctx, domain.NodeObservation{NodeID: riskNodeID, Online: true, Capabilities: `[]`, LastHeartbeat: now}); err != nil {
		t.Fatal(err)
	}
	finding := domain.DeploymentRiskObservation{Kind: "admin_api_non_loopback", Severity: "critical", Evidence: "redacted", Confidence: "high", RuleVersion: "1", ResourceFingerprint: strings.Repeat("c", 64)}
	if err = db.ReconcileDeploymentRisks(ctx, riskNodeID, "", "pass", "", []domain.DeploymentRiskObservation{finding}, []string{"admin_api_non_loopback"}, now); err != nil {
		t.Fatal(err)
	}
	if err = db.ReconcileDeploymentRisks(ctx, riskNodeID, "", "fail", "LOG_READ_FAILED", nil, []string{"proxy_name_conflict"}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	riskPage, err := db.ListDeploymentRisks(ctx, domain.DeploymentRiskFilter{NodeID: riskNodeID}, 10, "")
	if err != nil || len(riskPage.Items) != 1 || riskPage.Items[0].State != "open" {
		t.Fatalf("partial risk scan advanced unrelated rule: page=%+v err=%v", riskPage, err)
	}
	riskRevision := domain.ConfigRevision{ID: uuid.NewString(), NodeID: riskNodeID, Version: 1, EncryptedContent: []byte("encrypted-risk"), Nonce: []byte("123456789012"), SHA256: strings.Repeat("d", 64), Strategy: "restart", CreatedBy: userID, CreatedAt: now, Mode: "raw", SensitiveFields: "[]"}
	riskTask := domain.Task{ID: uuid.NewString(), Type: "risk_repair", State: "running", NodeID: riskNodeID, IdempotencyKey: "risk-repair-" + suffix, RequestedBy: userID, Payload: "{}", ConfigRevisionID: &riskRevision.ID, CreatedAt: now, UpdatedAt: now}
	riskStep := domain.TaskStep{ID: uuid.NewString(), TaskID: riskTask.ID, Name: "risk_repair", State: "running", Attempt: 1, CreatedAt: now, UpdatedAt: now}
	riskCtx := store.WithMutationAudit(ctx, store.MutationAudit{Actor: userID, Action: "deployment_risk.repair", Resource: "deployment-risk/" + riskPage.Items[0].ID, RequestID: "risk-" + suffix})
	if err = db.CreateDerivedDeploymentRiskRepairTask(riskCtx, riskPage.Items[0].ID, riskRevision, riskTask, riskStep); err != nil {
		t.Fatal(err)
	}
	if final, completeErr := db.CompleteConfigTask(ctx, riskTask, "succeeded", "", "", `{"changed":true}`, strings.Repeat("e", 64), now.Add(2*time.Second)); completeErr != nil || final.FinalState != "succeeded" {
		t.Fatalf("risk repair completion final=%+v err=%v", final, completeErr)
	}
	riskNode, err := db.NodeByID(ctx, riskNodeID)
	if err != nil || riskNode.DesiredRevisionID == nil || *riskNode.DesiredRevisionID != riskRevision.ID || riskNode.Observation == nil || riskNode.Observation.ObservedHash != strings.Repeat("e", 64) {
		t.Fatalf("risk repair desired/observed proof: node=%+v err=%v", riskNode, err)
	}
	resultAudits, err := db.ListAuditLogs(ctx, domain.AuditFilter{Action: "deployment_risk.repair.result"}, 20, "")
	if err != nil || len(resultAudits.Items) == 0 || resultAudits.Items[0].Outcome != "succeeded" {
		t.Fatalf("risk result audit: items=%+v err=%v", resultAudits.Items, err)
	}
	duplicateRevision := riskRevision
	duplicateRevision.ID = uuid.NewString()
	duplicateRevision.Version = 2
	duplicateTask := riskTask
	duplicateTask.ID = uuid.NewString()
	duplicateTask.ConfigRevisionID = &duplicateRevision.ID
	duplicateStep := riskStep
	duplicateStep.ID, duplicateStep.TaskID = uuid.NewString(), duplicateTask.ID
	if duplicateErr := db.CreateDerivedDeploymentRiskRepairTask(riskCtx, riskPage.Items[0].ID, duplicateRevision, duplicateTask, duplicateStep); !errors.Is(duplicateErr, store.ErrConflict) {
		t.Fatalf("risk idempotency conflict=%v", duplicateErr)
	}
	if err = db.ReconcileDeploymentRisks(ctx, riskNodeID, "", "pass", "", nil, []string{"admin_api_non_loopback"}, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = db.ReconcileDeploymentRisks(ctx, riskNodeID, "", "pass", "", nil, []string{"admin_api_non_loopback"}, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	riskPage, err = db.ListDeploymentRisks(ctx, domain.DeploymentRiskFilter{NodeID: riskNodeID}, 10, "")
	if err != nil || riskPage.Items[0].State != "resolved" {
		t.Fatalf("risk two-scan resolution: page=%+v err=%v", riskPage, err)
	}
}

func TestDatabaseMigrationReplay(t *testing.T) {
	dialect := os.Getenv("FRP_ADMIN_INTEGRATION_DB_DRIVER")
	dsn := os.Getenv("FRP_ADMIN_INTEGRATION_DB_DSN")
	if dialect == "" || dsn == "" {
		t.Skip("integration database is not configured")
	}
	if dialect != "mysql" {
		t.Skip("version 5 replay targets non-transactional MySQL DDL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	opened, err := sqlstore.Open(ctx, dialect, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err = opened.Close(); err != nil {
		t.Fatal(err)
	}
	driver := dialect
	if dialect == "postgres" {
		driver = "pgx"
	}
	raw, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.ExecContext(ctx, "DELETE FROM schema_migrations WHERE version=5"); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	replayed, err := sqlstore.Open(ctx, dialect, dsn)
	if err != nil {
		t.Fatalf("replay migration after missing version record: %v", err)
	}
	if err = replayed.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteMigrationReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := t.TempDir() + "/replay.db"
	opened, err := sqlstore.Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err = opened.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.ExecContext(ctx, "DELETE FROM schema_migrations WHERE version=4"); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	replayed, err := sqlstore.Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatalf("replay migration after missing version record: %v", err)
	}
	if err = replayed.Close(); err != nil {
		t.Fatal(err)
	}
}
