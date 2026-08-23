package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/auth"
	"github.com/frp-admin/frp-admin/server/internal/configcrypto"
	"github.com/frp-admin/frp-admin/server/internal/configuration"
	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/events"
	"github.com/frp-admin/frp-admin/server/internal/node"
	"github.com/frp-admin/frp-admin/server/internal/risk"
	"github.com/frp-admin/frp-admin/server/internal/secretmgr"
	"github.com/frp-admin/frp-admin/server/internal/store/sqlstore"
	"github.com/frp-admin/frp-admin/server/internal/task"
	"github.com/frp-admin/frp-admin/server/internal/upgrade"
	"github.com/google/uuid"
)

func TestBootstrapLoginAndEnrollmentToken(t *testing.T) {
	ctx := context.Background()
	s, err := sqlstore.Open(ctx, "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	authService := auth.New(s, "bootstrap-secret", time.Hour)
	bus := events.New()
	cipher, err := configcrypto.LoadOrCreate(t.TempDir() + "/master.key")
	if err != nil {
		t.Fatal(err)
	}
	secrets := secretmgr.New(s, cipher)
	configs := configuration.New(s, cipher, bus, secrets)
	tasks := task.New(s, nil, bus)
	h := New(authService, node.New(s), tasks, upgrade.New(s, nil, tasks, bus, time.Minute, cipher), configs, secrets, risk.New(s, nil, tasks, bus), s, bus, slog.New(slog.NewTextHandler(io.Discard, nil)), false, []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"))

	status := request(t, h, http.MethodGet, "/api/v1/auth/bootstrap-status", nil, nil)
	if status.Code != http.StatusOK || !bytes.Contains(status.Body.Bytes(), []byte(`"required":true`)) {
		t.Fatalf("unexpected bootstrap status: %d %s", status.Code, status.Body.String())
	}
	bootstrap := request(t, h, http.MethodPost, "/api/v1/auth/bootstrap", map[string]any{"username": "admin", "password": "a-secure-password", "bootstrapToken": "bootstrap-secret"}, nil)
	if bootstrap.Code != http.StatusCreated {
		t.Fatalf("bootstrap: %d %s", bootstrap.Code, bootstrap.Body.String())
	}
	var adminUser struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(bootstrap.Body.Bytes(), &adminUser); err != nil {
		t.Fatal(err)
	}
	login := request(t, h, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": "admin", "password": "a-secure-password"}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login: %d %s", login.Code, login.Body.String())
	}
	var session, csrf *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == sessionCookie {
			session = c
		}
		if c.Name == csrfCookie {
			csrf = c
		}
	}
	if session == nil || !session.HttpOnly || csrf == nil || csrf.HttpOnly {
		t.Fatal("expected HttpOnly session and readable CSRF cookies")
	}
	headers := map[string]string{"Cookie": sessionCookie + "=" + session.Value + "; " + csrfCookie + "=" + csrf.Value, "X-CSRF-Token": csrf.Value}
	secretCreated := request(t, h, http.MethodPost, "/api/v1/secrets", map[string]any{"name": "FRP_TOKEN", "value": "super-sensitive-value"}, headers)
	if secretCreated.Code != http.StatusCreated || bytes.Contains(secretCreated.Body.Bytes(), []byte("super-sensitive-value")) {
		t.Fatalf("secret create leaked: %d %s", secretCreated.Code, secretCreated.Body.String())
	}
	var secretRecord struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(secretCreated.Body.Bytes(), &secretRecord); err != nil {
		t.Fatal(err)
	}
	secretList := request(t, h, http.MethodGet, "/api/v1/secrets", nil, map[string]string{"Cookie": headers["Cookie"]})
	if secretList.Code != http.StatusOK || bytes.Contains(secretList.Body.Bytes(), []byte("super-sensitive-value")) {
		t.Fatalf("secret list leaked: %d %s", secretList.Code, secretList.Body.String())
	}
	secretUpdated := request(t, h, http.MethodPut, "/api/v1/secrets/"+secretRecord.ID, map[string]any{"value": "rotated-sensitive-value"}, headers)
	if secretUpdated.Code != http.StatusOK || bytes.Contains(secretUpdated.Body.Bytes(), []byte("rotated-sensitive-value")) {
		t.Fatalf("secret update leaked: %d %s", secretUpdated.Code, secretUpdated.Body.String())
	}
	ca := request(t, h, http.MethodGet, "/api/v1/system/agent-ca", nil, map[string]string{"Cookie": headers["Cookie"]})
	if ca.Code != http.StatusOK || ca.Header().Get("Content-Type") != "application/x-pem-file" || !bytes.Contains(ca.Body.Bytes(), []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("CA download: %d %s", ca.Code, ca.Body.String())
	}
	created := request(t, h, http.MethodPost, "/api/v1/nodes/enrollment-tokens", map[string]any{"role": "client", "ttlSeconds": 600}, headers)
	if created.Code != http.StatusCreated || !bytes.Contains(created.Body.Bytes(), []byte(`"token"`)) {
		t.Fatalf("create token: %d %s", created.Code, created.Body.String())
	}
	var enrollment struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &enrollment); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(enrollment.Token))
	now := time.Now().UTC()
	restrictedAlert := domain.Alert{ID: uuid.NewString(), Kind: "task_failed", Severity: "critical", State: "open", Resource: "task/restricted", Fingerprint: "task_failed:task/restricted", Message: "failed", CreatedAt: now, UpdatedAt: now}
	if err := s.CreateAlert(ctx, restrictedAlert); err != nil {
		t.Fatal(err)
	}
	nodeID := uuid.Must(uuid.NewV7()).String()
	if err := s.ConsumeEnrollmentTokenAndCreateNode(ctx, hex.EncodeToString(sum[:]), "client", domain.Node{ID: nodeID, Name: "offline-node", Role: "client", Labels: "{}", ManagementMode: "observe", CreatedAt: now, UpdatedAt: now}, now); err != nil {
		t.Fatal(err)
	}
	observeRuntime := request(t, h, http.MethodPost, "/api/v1/nodes/"+nodeID+"/runtime-collections", nil, headers)
	if observeRuntime.Code != http.StatusConflict || !bytes.Contains(observeRuntime.Body.Bytes(), []byte("does not support runtime collection")) {
		t.Fatalf("runtime collection without capability was not rejected explicitly: %d %s", observeRuntime.Code, observeRuntime.Body.String())
	}
	observeService := request(t, h, http.MethodPost, "/api/v1/nodes/"+nodeID+"/service-actions", map[string]any{"action": "restart"}, headers)
	if observeService.Code != http.StatusConflict {
		t.Fatalf("observe node service mutation accepted: %d %s", observeService.Code, observeService.Body.String())
	}
	observeConfig := request(t, h, http.MethodPost, "/api/v1/nodes/"+nodeID+"/config-revisions", map[string]any{"content": "serverAddr = \"example.test\"\n", "strategy": "restart"}, headers)
	if observeConfig.Code != http.StatusConflict {
		t.Fatalf("observe node config mutation accepted: %d %s", observeConfig.Code, observeConfig.Body.String())
	}
	observeUpgradeHeaders := maps.Clone(headers)
	observeUpgradeHeaders["Idempotency-Key"] = "observe-upgrade"
	observeUpgrade := request(t, h, http.MethodPost, "/api/v1/upgrade-plans", map[string]any{"node_id": nodeID, "version": "v0.70.0", "artifact_url": "https://download.example/frp", "sha256": strings.Repeat("a", 64)}, observeUpgradeHeaders)
	if observeUpgrade.Code != http.StatusConflict {
		t.Fatalf("observe node upgrade accepted: %d %s", observeUpgrade.Code, observeUpgrade.Body.String())
	}
	modeResponse := request(t, h, http.MethodPatch, "/api/v1/nodes/"+nodeID+"/management-mode", map[string]any{"mode": "managed"}, headers)
	if modeResponse.Code != http.StatusOK || !bytes.Contains(modeResponse.Body.Bytes(), []byte(`"management_mode":"managed"`)) {
		t.Fatalf("set node management mode: %d %s", modeResponse.Code, modeResponse.Body.String())
	}
	missingInspectCapability := request(t, h, http.MethodPost, "/api/v1/nodes/"+nodeID+"/inspect", nil, headers)
	if missingInspectCapability.Code != http.StatusConflict || !bytes.Contains(missingInspectCapability.Body.Bytes(), []byte("does not support inspect")) {
		t.Fatalf("inspect capability response: %d %s", missingInspectCapability.Code, missingInspectCapability.Body.String())
	}
	missingServiceCapability := request(t, h, http.MethodPost, "/api/v1/nodes/"+nodeID+"/service-actions", map[string]any{"action": "restart"}, headers)
	if missingServiceCapability.Code != http.StatusConflict || !bytes.Contains(missingServiceCapability.Body.Bytes(), []byte("does not support this service action")) {
		t.Fatalf("service capability response: %d %s", missingServiceCapability.Code, missingServiceCapability.Body.String())
	}
	capabilityRevisionResponse := request(t, h, http.MethodPost, "/api/v1/nodes/"+nodeID+"/config-revisions", map[string]any{"content": "serverAddr = \"capability.example\"\n", "strategy": "restart"}, headers)
	if capabilityRevisionResponse.Code != http.StatusCreated {
		t.Fatalf("create capability-test revision: %d %s", capabilityRevisionResponse.Code, capabilityRevisionResponse.Body.String())
	}
	var capabilityRevision struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(capabilityRevisionResponse.Body.Bytes(), &capabilityRevision); err != nil {
		t.Fatal(err)
	}
	missingConfigCapability := request(t, h, http.MethodPost, "/api/v1/config-revisions/"+capabilityRevision.ID+"/deploy", nil, headers)
	if missingConfigCapability.Code != http.StatusConflict || !bytes.Contains(missingConfigCapability.Body.Bytes(), []byte("does not support configuration deployment")) {
		t.Fatalf("config capability response: %d %s", missingConfigCapability.Code, missingConfigCapability.Body.String())
	}
	missingUpgradeCapabilityHeaders := maps.Clone(headers)
	missingUpgradeCapabilityHeaders["Idempotency-Key"] = "missing-upgrade-capability"
	missingUpgradeCapability := request(t, h, http.MethodPost, "/api/v1/upgrade-plans", map[string]any{"node_id": nodeID, "version": "v0.70.0", "artifact_url": "https://download.example/frp", "sha256": strings.Repeat("a", 64)}, missingUpgradeCapabilityHeaders)
	if missingUpgradeCapability.Code != http.StatusConflict || !bytes.Contains(missingUpgradeCapability.Body.Bytes(), []byte("does not support upgrades")) {
		t.Fatalf("upgrade capability response: %d %s", missingUpgradeCapability.Code, missingUpgradeCapability.Body.String())
	}
	if err := s.UpsertObservation(ctx, domain.NodeObservation{NodeID: nodeID, Online: true, ServiceState: "active", Capabilities: `["inspect","runtime.collect","service.start","service.stop","service.restart","config.apply","config.rollback","frp.upgrade","risk.scan","risk.repair.config_permissions","risk.repair.admin_loopback"]`, LastHeartbeat: now}); err != nil {
		t.Fatal(err)
	}
	findings := []domain.DeploymentRiskObservation{
		{Kind: "config_token_permissions", Severity: "critical", Evidence: "mode=0644; token=redacted", Confidence: "high", RuleVersion: "1", ResourceFingerprint: strings.Repeat("a", 64)},
		{Kind: "admin_api_non_loopback", Severity: "critical", Evidence: "listen=0.0.0.0:7500", Confidence: "high", RuleVersion: "1", ResourceFingerprint: strings.Repeat("b", 64)},
	}
	if err := s.ReconcileDeploymentRisks(ctx, nodeID, "", "pass", "", findings, []string{"admin_api_non_loopback", "config_token_permissions", "proxy_name_conflict"}, now); err != nil {
		t.Fatal(err)
	}
	riskList := request(t, h, http.MethodGet, "/api/v1/risks?node_id="+nodeID, nil, map[string]string{"Cookie": headers["Cookie"]})
	if riskList.Code != http.StatusOK || !bytes.Contains(riskList.Body.Bytes(), []byte(`"allowed_actions":["restrict_config_permissions"]`)) || bytes.Contains(riskList.Body.Bytes(), []byte("super-sensitive-value")) {
		t.Fatalf("risk list: %d %s", riskList.Code, riskList.Body.String())
	}
	missingRiskScanKey := request(t, h, http.MethodPost, "/api/v1/nodes/"+nodeID+"/risk-scans", nil, headers)
	if missingRiskScanKey.Code != http.StatusBadRequest {
		t.Fatalf("risk scan accepted without idempotency key: %d %s", missingRiskScanKey.Code, missingRiskScanKey.Body.String())
	}
	riskScanHeaders := maps.Clone(headers)
	riskScanHeaders["Idempotency-Key"] = "risk-scan-once"
	riskScan := request(t, h, http.MethodPost, "/api/v1/nodes/"+nodeID+"/risk-scans", nil, riskScanHeaders)
	if riskScan.Code != http.StatusAccepted || !bytes.Contains(riskScan.Body.Bytes(), []byte(`"type":"risk_scan"`)) {
		t.Fatalf("risk scan: %d %s", riskScan.Code, riskScan.Body.String())
	}
	var riskScanTask struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(riskScan.Body.Bytes(), &riskScanTask); err != nil {
		t.Fatal(err)
	}
	riskScanReplay := request(t, h, http.MethodPost, "/api/v1/nodes/"+nodeID+"/risk-scans", nil, riskScanHeaders)
	if riskScanReplay.Code != http.StatusAccepted || !bytes.Contains(riskScanReplay.Body.Bytes(), []byte(`"id":"`+riskScanTask.ID+`"`)) {
		t.Fatalf("risk scan idempotency replay: %d %s", riskScanReplay.Code, riskScanReplay.Body.String())
	}
	riskPage, err := s.ListDeploymentRisks(ctx, domain.DeploymentRiskFilter{NodeID: nodeID}, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	var permissionRisk, bindRisk domain.DeploymentRisk
	for _, finding := range riskPage.Items {
		if finding.Kind == "config_token_permissions" {
			permissionRisk = finding
		}
		if finding.Kind == "admin_api_non_loopback" {
			bindRisk = finding
		}
	}
	missingRiskRepairKey := request(t, h, http.MethodPost, "/api/v1/risks/"+bindRisk.ID+"/repairs", map[string]any{"action": "bind_admin_api_loopback", "maintenance_confirmed": true}, headers)
	if missingRiskRepairKey.Code != http.StatusBadRequest {
		t.Fatalf("risk repair accepted without idempotency key: %d %s", missingRiskRepairKey.Code, missingRiskRepairKey.Body.String())
	}
	maintenanceHeaders := maps.Clone(headers)
	maintenanceHeaders["Idempotency-Key"] = "bind-maintenance-check"
	missingMaintenance := request(t, h, http.MethodPost, "/api/v1/risks/"+bindRisk.ID+"/repairs", map[string]any{"action": "bind_admin_api_loopback", "maintenance_confirmed": false}, maintenanceHeaders)
	if missingMaintenance.Code != http.StatusPreconditionRequired {
		t.Fatalf("bind repair accepted without maintenance confirmation: %d %s", missingMaintenance.Code, missingMaintenance.Body.String())
	}
	riskHeaders := maps.Clone(headers)
	riskHeaders["Idempotency-Key"] = "risk-repair-once"
	repair := request(t, h, http.MethodPost, "/api/v1/risks/"+permissionRisk.ID+"/repairs", map[string]any{"action": "restrict_config_permissions"}, riskHeaders)
	if repair.Code != http.StatusAccepted || !bytes.Contains(repair.Body.Bytes(), []byte(`"type":"risk_repair"`)) {
		t.Fatalf("risk repair: %d %s", repair.Code, repair.Body.String())
	}
	var repairTask struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(repair.Body.Bytes(), &repairTask); err != nil {
		t.Fatal(err)
	}
	replay := request(t, h, http.MethodPost, "/api/v1/risks/"+permissionRisk.ID+"/repairs", map[string]any{"action": "restrict_config_permissions"}, riskHeaders)
	if replay.Code != http.StatusAccepted || !bytes.Contains(replay.Body.Bytes(), []byte(`"id":"`+repairTask.ID+`"`)) {
		t.Fatalf("risk repair idempotency replay: %d %s", replay.Code, replay.Body.String())
	}
	if cancelledRisk := request(t, h, http.MethodPost, "/api/v1/tasks/"+repairTask.ID+"/cancel", nil, headers); cancelledRisk.Code != http.StatusOK {
		t.Fatalf("cancel risk task: %d %s", cancelledRisk.Code, cancelledRisk.Body.String())
	}
	runtimeSnapshot := domain.RuntimeSnapshot{NodeID: nodeID, Role: "client", FRPVersion: "v0.70.0", CollectedAt: now, ProxyCount: 1, Proxies: []domain.RuntimeProxy{{NodeID: nodeID, Name: "ssh", Type: "tcp", Status: "running", LocalAddress: "127.0.0.1:22", RemoteAddress: ":6000", Traffic: domain.RuntimeTraffic{BytesIn: 10, BytesOut: 20}, CollectedAt: now}}, Clients: []domain.RuntimeClient{}}
	if err := s.ReplaceRuntimeSnapshot(ctx, runtimeSnapshot); err != nil {
		t.Fatal(err)
	}
	runtimeResponse := request(t, h, http.MethodGet, "/api/v1/nodes/"+nodeID+"/runtime", nil, map[string]string{"Cookie": headers["Cookie"]})
	if runtimeResponse.Code != http.StatusOK || !bytes.Contains(runtimeResponse.Body.Bytes(), []byte(`"name":"ssh"`)) || !bytes.Contains(runtimeResponse.Body.Bytes(), []byte(`"traffic":{"bytes_in":10,"bytes_out":20`)) {
		t.Fatalf("runtime detail contract: %d %s", runtimeResponse.Code, runtimeResponse.Body.String())
	}
	proxyResponse := request(t, h, http.MethodGet, "/api/v1/proxies?nodeId="+nodeID+"&status=running&type=tcp", nil, map[string]string{"Cookie": headers["Cookie"]})
	if proxyResponse.Code != http.StatusOK || !bytes.Contains(proxyResponse.Body.Bytes(), []byte(`"node_name":"offline-node"`)) || !bytes.Contains(proxyResponse.Body.Bytes(), []byte(`"collected_at"`)) {
		t.Fatalf("proxy list contract: %d %s", proxyResponse.Code, proxyResponse.Body.String())
	}
	missingIdempotency := request(t, h, http.MethodPost, "/api/v1/upgrade-plans", map[string]any{"node_id": nodeID, "version": "v0.70.0", "artifact_url": "https://download.example/frp.tar.gz?token=presigned-secret", "sha256": strings.Repeat("a", 64)}, headers)
	if missingIdempotency.Code != http.StatusBadRequest {
		t.Fatalf("upgrade accepted without idempotency key: %d %s", missingIdempotency.Code, missingIdempotency.Body.String())
	}
	upgradeHeaders := maps.Clone(headers)
	upgradeHeaders["Idempotency-Key"] = "upgrade-once"
	upgradeResponse := request(t, h, http.MethodPost, "/api/v1/upgrade-plans", map[string]any{"node_id": nodeID, "version": "v0.70.0", "artifact_url": "https://download.example/frp.tar.gz?token=presigned-secret", "sha256": strings.Repeat("a", 64)}, upgradeHeaders)
	if upgradeResponse.Code != http.StatusAccepted || bytes.Contains(upgradeResponse.Body.Bytes(), []byte("presigned-secret")) || !bytes.Contains(upgradeResponse.Body.Bytes(), []byte("https://download.example/frp.tar.gz")) {
		t.Fatalf("upgrade response leaked or omitted display URL: %d %s", upgradeResponse.Code, upgradeResponse.Body.String())
	}
	var upgradeCreated struct {
		Plan struct {
			ID string `json:"id"`
		} `json:"plan"`
		Task struct {
			ID string `json:"id"`
		} `json:"task"`
	}
	if err := json.Unmarshal(upgradeResponse.Body.Bytes(), &upgradeCreated); err != nil {
		t.Fatal(err)
	}
	storedPlan, err := s.UpgradePlanByID(ctx, upgradeCreated.Plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedPlan.ArtifactURL != "" || bytes.Contains(storedPlan.ArtifactCiphertext, []byte("presigned-secret")) || storedPlan.ArtifactKeyVersion == "" {
		t.Fatal("upgrade artifact URL was not encrypted at rest")
	}
	storedTask, err := s.TaskByID(ctx, upgradeCreated.Task.ID)
	if err != nil || strings.Contains(storedTask.Payload, "presigned-secret") || storedTask.Payload != "{}" {
		t.Fatalf("upgrade task leaked artifact URL: payload=%q err=%v", storedTask.Payload, err)
	}
	duplicateUpgrade := request(t, h, http.MethodPost, "/api/v1/upgrade-plans", map[string]any{"node_id": nodeID, "version": "v0.70.0", "artifact_url": "https://download.example/frp.tar.gz?token=other", "sha256": strings.Repeat("a", 64)}, upgradeHeaders)
	if duplicateUpgrade.Code != http.StatusConflict {
		t.Fatalf("duplicate upgrade idempotency key accepted: %d %s", duplicateUpgrade.Code, duplicateUpgrade.Body.String())
	}
	unsafeObserve := request(t, h, http.MethodPatch, "/api/v1/nodes/"+nodeID+"/management-mode", map[string]any{"mode": "observe"}, headers)
	if unsafeObserve.Code != http.StatusConflict {
		t.Fatalf("node switched to observe with active managed task: %d %s", unsafeObserve.Code, unsafeObserve.Body.String())
	}
	cancelUpgrade := request(t, h, http.MethodPost, "/api/v1/upgrade-plans/"+upgradeCreated.Plan.ID+"/cancel", nil, headers)
	if cancelUpgrade.Code != http.StatusOK {
		t.Fatalf("cancel upgrade plan: %d %s", cancelUpgrade.Code, cancelUpgrade.Body.String())
	}
	inspect := request(t, h, http.MethodPost, "/api/v1/nodes/"+nodeID+"/inspect", nil, headers)
	if inspect.Code != http.StatusAccepted || !bytes.Contains(inspect.Body.Bytes(), []byte(`"status":"queued"`)) {
		t.Fatalf("inspect: %d %s", inspect.Code, inspect.Body.String())
	}
	service := request(t, h, http.MethodPost, "/api/v1/nodes/"+nodeID+"/service-actions", map[string]any{"action": "restart"}, headers)
	if service.Code != http.StatusAccepted || !bytes.Contains(service.Body.Bytes(), []byte(`"type":"service_restart"`)) {
		t.Fatalf("service action: %d %s", service.Code, service.Body.String())
	}
	var serviceTask struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(service.Body.Bytes(), &serviceTask); err != nil {
		t.Fatal(err)
	}
	cancelled := request(t, h, http.MethodPost, "/api/v1/tasks/"+serviceTask.ID+"/cancel", nil, headers)
	if cancelled.Code != http.StatusOK || !bytes.Contains(cancelled.Body.Bytes(), []byte(`"status":"cancelled"`)) {
		t.Fatalf("cancel task: %d %s", cancelled.Code, cancelled.Body.String())
	}
	if again := request(t, h, http.MethodPost, "/api/v1/tasks/"+serviceTask.ID+"/cancel", nil, headers); again.Code != http.StatusConflict {
		t.Fatalf("terminal task cancelled twice: %d %s", again.Code, again.Body.String())
	}
	badAction := request(t, h, http.MethodPost, "/api/v1/nodes/"+nodeID+"/service-actions", map[string]any{"action": "systemctl restart frpc"}, headers)
	if badAction.Code != http.StatusBadRequest {
		t.Fatalf("arbitrary service command accepted: %d", badAction.Code)
	}
	metricsResponse := request(t, h, http.MethodGet, "/metrics", nil, nil)
	if metricsResponse.Code != http.StatusNotFound {
		t.Fatalf("metrics exposed on business listener: %d", metricsResponse.Code)
	}
	rawConfig := "serverAddr = \"secret.example\"\nserverPort = 7000\n[auth]\ntoken = \"${secret:FRP_TOKEN}\"\n"
	revisionResponse := request(t, h, http.MethodPost, "/api/v1/nodes/"+nodeID+"/config-revisions", map[string]any{"content": rawConfig, "format": "toml", "strategy": "reload"}, headers)
	if revisionResponse.Code != http.StatusCreated || !bytes.Contains(revisionResponse.Body.Bytes(), []byte(`"format":"toml"`)) {
		t.Fatalf("revision: %d %s", revisionResponse.Code, revisionResponse.Body.String())
	}
	if !bytes.Contains(revisionResponse.Body.Bytes(), []byte("auth.token")) || bytes.Contains(revisionResponse.Body.Bytes(), []byte("rotated-sensitive-value")) {
		t.Fatalf("sensitive metadata invalid: %s", revisionResponse.Body.String())
	}
	var revision struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(revisionResponse.Body.Bytes(), &revision); err != nil {
		t.Fatal(err)
	}
	stored, err := s.ConfigRevisionByID(ctx, revision.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored.EncryptedContent, []byte("secret.example")) {
		t.Fatal("configuration stored in plaintext")
	}
	materialized, err := configs.Materialize(ctx, revision.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(materialized.Content, []byte("rotated-sensitive-value")) || bytes.Contains(materialized.Content, []byte("${secret:")) {
		t.Fatalf("secret was not materialized safely: %s", materialized.Content)
	}
	listed := request(t, h, http.MethodGet, "/api/v1/nodes/"+nodeID+"/config-revisions", nil, map[string]string{"Cookie": headers["Cookie"]})
	if listed.Code != http.StatusOK || bytes.Contains(listed.Body.Bytes(), []byte("secret.example")) {
		t.Fatalf("list revisions: %d %s", listed.Code, listed.Body.String())
	}
	contentResponse := request(t, h, http.MethodGet, "/api/v1/config-revisions/"+revision.ID+"/content", nil, map[string]string{"Cookie": headers["Cookie"]})
	if contentResponse.Code != http.StatusOK || !bytes.Contains(contentResponse.Body.Bytes(), []byte("secret.example")) {
		t.Fatalf("revision content: %d %s", contentResponse.Code, contentResponse.Body.String())
	}
	deploy := request(t, h, http.MethodPost, "/api/v1/config-revisions/"+revision.ID+"/deploy", nil, headers)
	if deploy.Code != http.StatusAccepted || !bytes.Contains(deploy.Body.Bytes(), []byte(`"status":"queued"`)) {
		t.Fatalf("deploy: %d %s", deploy.Code, deploy.Body.String())
	}
	rollbackConflict := request(t, h, http.MethodPost, "/api/v1/nodes/"+nodeID+"/config-rollbacks", map[string]any{"revision_id": revision.ID}, headers)
	if rollbackConflict.Code != http.StatusConflict {
		t.Fatalf("parallel node mutation accepted: %d %s", rollbackConflict.Code, rollbackConflict.Body.String())
	}
	var deployTask struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(deploy.Body.Bytes(), &deployTask); err != nil {
		t.Fatal(err)
	}
	if cancelledDeploy := request(t, h, http.MethodPost, "/api/v1/tasks/"+deployTask.ID+"/cancel", nil, headers); cancelledDeploy.Code != http.StatusOK {
		t.Fatalf("cancel deploy: %d %s", cancelledDeploy.Code, cancelledDeploy.Body.String())
	}
	rollback := request(t, h, http.MethodPost, "/api/v1/nodes/"+nodeID+"/config-rollbacks", map[string]any{"revision_id": revision.ID}, headers)
	if rollback.Code != http.StatusAccepted {
		t.Fatalf("rollback after cancel: %d %s", rollback.Code, rollback.Body.String())
	}
	userCreated := request(t, h, http.MethodPost, "/api/v1/users", map[string]any{"username": "viewer-user", "password": "viewer-password-123", "role": "viewer"}, headers)
	if userCreated.Code != http.StatusCreated {
		t.Fatalf("create user: %d %s", userCreated.Code, userCreated.Body.String())
	}
	var viewer struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(userCreated.Body.Bytes(), &viewer)
	viewerLogin := request(t, h, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": "viewer-user", "password": "viewer-password-123"}, nil)
	if viewerLogin.Code != http.StatusOK {
		t.Fatal(viewerLogin.Body.String())
	}
	viewerCookie := ""
	for _, c := range viewerLogin.Result().Cookies() {
		if c.Name == sessionCookie {
			viewerCookie = sessionCookie + "=" + c.Value
		}
	}
	forbiddenContent := request(t, h, http.MethodGet, "/api/v1/config-revisions/"+revision.ID+"/content", nil, map[string]string{"Cookie": viewerCookie})
	if forbiddenContent.Code != http.StatusForbidden {
		t.Fatalf("viewer read content: %d", forbiddenContent.Code)
	}
	viewerMetadata := request(t, h, http.MethodGet, "/api/v1/nodes/"+nodeID+"/config-revisions", nil, map[string]string{"Cookie": viewerCookie})
	if viewerMetadata.Code != http.StatusOK || bytes.Contains(viewerMetadata.Body.Bytes(), []byte("serverAddr")) {
		t.Fatalf("viewer metadata boundary: %d %s", viewerMetadata.Code, viewerMetadata.Body.String())
	}
	viewerUpgrade := request(t, h, http.MethodPost, "/api/v1/upgrade-plans", map[string]any{"node_id": nodeID, "version": "v0.70.1", "artifact_url": "https://download.example/frp.tar.gz", "sha256": strings.Repeat("b", 64)}, map[string]string{"Cookie": viewerCookie, "Idempotency-Key": "viewer-upgrade"})
	if viewerUpgrade.Code != http.StatusForbidden {
		t.Fatalf("viewer created upgrade plan: %d %s", viewerUpgrade.Code, viewerUpgrade.Body.String())
	}
	viewerCollection := request(t, h, http.MethodPost, "/api/v1/nodes/"+nodeID+"/runtime-collections", nil, map[string]string{"Cookie": viewerCookie})
	if viewerCollection.Code != http.StatusForbidden {
		t.Fatalf("viewer collected runtime: %d %s", viewerCollection.Code, viewerCollection.Body.String())
	}
	viewerMode := request(t, h, http.MethodPatch, "/api/v1/nodes/"+nodeID+"/management-mode", map[string]any{"mode": "observe"}, map[string]string{"Cookie": viewerCookie})
	if viewerMode.Code != http.StatusForbidden {
		t.Fatalf("viewer changed management mode: %d %s", viewerMode.Code, viewerMode.Body.String())
	}
	viewerClose := request(t, h, http.MethodPost, "/api/v1/alerts/"+restrictedAlert.ID+"/close", nil, map[string]string{"Cookie": viewerCookie})
	if viewerClose.Code != http.StatusForbidden {
		t.Fatalf("viewer closed alert: %d", viewerClose.Code)
	}
	viewerAlerts := request(t, h, http.MethodGet, "/api/v1/alerts", nil, map[string]string{"Cookie": viewerCookie})
	if viewerAlerts.Code != http.StatusOK {
		t.Fatalf("viewer alerts: %d %s", viewerAlerts.Code, viewerAlerts.Body.String())
	}
	disable := request(t, h, http.MethodPatch, "/api/v1/users/"+viewer.ID, map[string]any{"status": "disabled"}, headers)
	if disable.Code != http.StatusOK {
		t.Fatalf("disable user: %d %s", disable.Code, disable.Body.String())
	}
	viewerMe := request(t, h, http.MethodGet, "/api/v1/users/me", nil, map[string]string{"Cookie": viewerCookie})
	if viewerMe.Code != http.StatusUnauthorized {
		t.Fatalf("disabled session still active: %d", viewerMe.Code)
	}
	lastAdmin := request(t, h, http.MethodPatch, "/api/v1/users/"+adminUser.ID, map[string]any{"status": "disabled"}, headers)
	if lastAdmin.Code != http.StatusConflict {
		t.Fatalf("last admin disabled: %d %s", lastAdmin.Code, lastAdmin.Body.String())
	}
	alertRecord := domain.Alert{ID: uuid.NewString(), Kind: "task_timeout", Severity: "critical", State: "open", Resource: "task/api", Fingerprint: "task_timeout:task/api", Message: "deadline exceeded", CreatedAt: now, UpdatedAt: now}
	if err := s.CreateAlert(ctx, alertRecord); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"acknowledge", "resolve", "close"} {
		response := request(t, h, http.MethodPost, "/api/v1/alerts/"+alertRecord.ID+"/"+action, nil, headers)
		if response.Code != http.StatusOK {
			t.Fatalf("alert %s: %d %s", action, response.Code, response.Body.String())
		}
	}
	if duplicate := request(t, h, http.MethodPost, "/api/v1/alerts/"+alertRecord.ID+"/acknowledge", nil, headers); duplicate.Code != http.StatusConflict {
		t.Fatalf("alert state regressed: %d", duplicate.Code)
	}
	alertAudit := request(t, h, http.MethodGet, "/api/v1/audit-logs?action=alert.closed", nil, map[string]string{"Cookie": headers["Cookie"]})
	if alertAudit.Code != http.StatusOK || !bytes.Contains(alertAudit.Body.Bytes(), []byte("alert.closed")) {
		t.Fatalf("alert audit: %d %s", alertAudit.Code, alertAudit.Body.String())
	}
	audits := request(t, h, http.MethodGet, "/api/v1/audit-logs?action=secret.create", nil, map[string]string{"Cookie": headers["Cookie"]})
	if audits.Code != http.StatusOK || !bytes.Contains(audits.Body.Bytes(), []byte("secret.create")) || bytes.Contains(audits.Body.Bytes(), []byte("sensitive-value")) {
		t.Fatalf("audit leak: %d %s", audits.Code, audits.Body.String())
	}
	upgradeAudits := request(t, h, http.MethodGet, "/api/v1/audit-logs?action=upgrade_plan.create", nil, map[string]string{"Cookie": headers["Cookie"]})
	if upgradeAudits.Code != http.StatusOK || !bytes.Contains(upgradeAudits.Body.Bytes(), []byte("upgrade_plan.create")) || bytes.Contains(upgradeAudits.Body.Bytes(), []byte("presigned-secret")) {
		t.Fatalf("upgrade audit leak or omission: %d %s", upgradeAudits.Code, upgradeAudits.Body.String())
	}
	modeAudits := request(t, h, http.MethodGet, "/api/v1/audit-logs?action=node.management_mode.update", nil, map[string]string{"Cookie": headers["Cookie"]})
	if modeAudits.Code != http.StatusOK || !bytes.Contains(modeAudits.Body.Bytes(), []byte("node.management_mode.update")) {
		t.Fatalf("management mode audit missing: %d %s", modeAudits.Code, modeAudits.Body.String())
	}
	_, serverToken, err := node.New(s).CreateEnrollmentToken(ctx, "server", adminUser.ID, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	serverSum := sha256.Sum256([]byte(serverToken))
	serverNodeID := uuid.Must(uuid.NewV7()).String()
	if err = s.ConsumeEnrollmentTokenAndCreateNode(ctx, hex.EncodeToString(serverSum[:]), "server", domain.Node{ID: serverNodeID, Name: "server-node", Role: "server", Labels: "{}", ManagementMode: "observe", CreatedAt: now, UpdatedAt: now}, now); err != nil {
		t.Fatal(err)
	}
	if response := request(t, h, http.MethodPatch, "/api/v1/nodes/"+serverNodeID+"/management-mode", map[string]any{"mode": "managed"}, headers); response.Code != http.StatusOK {
		t.Fatalf("set server node management mode: %d %s", response.Code, response.Body.String())
	}
	badReload := request(t, h, http.MethodPost, "/api/v1/nodes/"+serverNodeID+"/config-revisions", map[string]any{"content": "bindPort = 7000\n", "strategy": "reload"}, headers)
	if badReload.Code != http.StatusBadRequest {
		t.Fatalf("server reload accepted: %d %s", badReload.Code, badReload.Body.String())
	}
	nodes := request(t, h, http.MethodGet, "/api/v1/nodes", nil, map[string]string{"Cookie": headers["Cookie"]})
	if nodes.Code != http.StatusOK || !bytes.Contains(nodes.Body.Bytes(), []byte(`"id":"`+nodeID+`"`)) || !bytes.Contains(nodes.Body.Bytes(), []byte(`"next_cursor"`)) {
		t.Fatalf("nodes: %d %s", nodes.Code, nodes.Body.String())
	}
}

func TestProblemDoesNotExposeInternalErrorDetails(t *testing.T) {
	secret := "mysql://operator:database-secret@db.internal/frp"
	for _, status := range []int{http.StatusBadRequest, http.StatusConflict, http.StatusInternalServerError} {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		problem(recorder, req, status, "request failed", errors.New(secret))
		if strings.Contains(recorder.Body.String(), secret) || strings.Contains(recorder.Body.String(), "detail") {
			t.Fatalf("status %d exposed internal error: %s", status, recorder.Body.String())
		}
	}
}

func TestTaskDTODoesNotExposeStoredDiagnostic(t *testing.T) {
	secret := "token=top-secret"
	task := domain.Task{ID: "task-1", Type: "config_apply", State: "failed", ErrorCode: "VERIFY_FAILED", ErrorMessage: secret,
		Steps: []domain.TaskStep{{ID: "step-1", State: "failed", ErrorCode: "VERIFY_FAILED", Output: secret}}}
	body, err := json.Marshal(taskDTO(task))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(secret)) || !bytes.Contains(body, []byte("candidate configuration verification failed")) {
		t.Fatalf("unsafe task DTO: %s", body)
	}
}

func request(t *testing.T, h http.Handler, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	r := httptest.NewRequest(method, path, reader)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
