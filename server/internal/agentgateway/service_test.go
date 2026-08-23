package agentgateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
	"github.com/frp-admin/frp-admin/server/internal/config"
	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/events"
	"github.com/frp-admin/frp-admin/server/internal/node"
	"github.com/frp-admin/frp-admin/server/internal/pki"
	"github.com/frp-admin/frp-admin/server/internal/store/sqlstore"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestSafeCapabilitiesAllowlistAndDeduplicate(t *testing.T) {
	got := safeCapabilities([]string{"risk.scan", "unknown", "risk.scan", "risk.repair.admin_loopback"})
	if len(got) != 2 || got[0] != "risk.scan" || got[1] != "risk.repair.admin_loopback" {
		t.Fatalf("capabilities=%v", got)
	}
}

func TestRequiredTaskCapability(t *testing.T) {
	want := map[string]string{
		"inspect":         "inspect",
		"risk_scan":       "risk.scan",
		"collect_runtime": "runtime.collect",
		"config_apply":    "config.apply",
		"config_rollback": "config.rollback",
		"service_start":   "service.start",
		"service_stop":    "service.stop",
		"service_restart": "service.restart",
		"frp_upgrade":     "frp.upgrade",
	}
	for taskType, capability := range want {
		if got := requiredTaskCapability(taskType); got != capability {
			t.Fatalf("task=%s capability=%s want=%s", taskType, got, capability)
		}
	}
	if got := requiredTaskCapability("risk_repair"); got != "" {
		t.Fatalf("risk repair uses action-specific capability, got=%s", got)
	}
}

func TestDispatchRejectsCapabilityMissingFromCurrentSession(t *testing.T) {
	f := newFixture(t)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.cert}, VerifiedChains: [][]*x509.Certificate{{f.cert}}}}})
	stream := newTestStream(ctx)
	done := make(chan error, 1)
	go func() { done <- f.service.Connect(stream) }()
	stream.recv <- helloWithoutCapabilities(f.response.NodeId)
	receiveServerFrame(t, stream, done)
	deadline := time.Now().Add(time.Second)
	for !f.service.Connected(f.response.NodeId) {
		if time.Now().After(deadline) {
			t.Fatal("session was not installed")
		}
		time.Sleep(time.Millisecond)
	}
	err := f.service.Dispatch(context.Background(), Command{ID: uuid.NewString(), NodeID: f.response.NodeId, Type: "service_restart"})
	if !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("dispatch error=%v", err)
	}
	close(stream.recv)
}

func TestRiskScanDispatchUsesRiskCapabilityAndInspectCommand(t *testing.T) {
	f := newFixture(t)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.cert}, VerifiedChains: [][]*x509.Certificate{{f.cert}}}}})
	stream := newTestStream(ctx)
	done := make(chan error, 1)
	go func() { done <- f.service.Connect(stream) }()
	helloMessage := helloWithoutCapabilities(f.response.NodeId)
	helloMessage.GetHello().Capabilities = []string{"risk.scan"}
	stream.recv <- helloMessage
	receiveServerFrame(t, stream, done)

	if err := f.service.Dispatch(context.Background(), Command{ID: uuid.NewString(), NodeID: f.response.NodeId, Type: "risk_scan"}); err != nil {
		t.Fatal(err)
	}
	frame := receiveServerFrame(t, stream, done)
	if frame.GetCommand().GetInspect() == nil {
		t.Fatalf("risk scan was not encoded as inspect command: %v", frame)
	}
	if err := f.service.Dispatch(context.Background(), Command{ID: uuid.NewString(), NodeID: f.response.NodeId, Type: "inspect"}); !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("plain inspect unexpectedly accepted with only risk.scan: %v", err)
	}
	close(stream.recv)
}

func TestConnectRejectsUnsupportedProtocolVersion(t *testing.T) {
	f := newFixture(t)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.cert}, VerifiedChains: [][]*x509.Certificate{{f.cert}}}}})
	stream := newTestStream(ctx)
	bad := hello(f.response.NodeId)
	bad.GetHello().ProtocolVersion = 2
	stream.recv <- bad
	close(stream.recv)
	if err := f.service.Connect(stream); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unsupported protocol code=%v err=%v", status.Code(err), err)
	}
}

func TestQueuedRiskCommandsRequireCurrentSessionCapability(t *testing.T) {
	for _, tc := range []struct {
		name, taskType, payload, errorCode string
	}{
		{name: "scan", taskType: "risk_scan", payload: `{}`, errorCode: "CAPABILITY_UNAVAILABLE"},
		{name: "repair", taskType: "risk_repair", payload: `{"FindingID":"finding-1","Kind":"config_token_permissions","Action":"restrict_config_permissions"}`, errorCode: "CAPABILITY_UNAVAILABLE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			now := time.Now().UTC()
			task := domain.Task{ID: uuid.NewString(), Type: tc.taskType, State: "queued", NodeID: f.response.NodeId, IdempotencyKey: uuid.NewString(), RequestedBy: f.adminID, Payload: tc.payload, CreatedAt: now, UpdatedAt: now}
			step := domain.TaskStep{ID: uuid.NewString(), TaskID: task.ID, Name: tc.taskType, State: "queued", Attempt: 1, CreatedAt: now, UpdatedAt: now}
			if err := f.store.CreateTask(context.Background(), task, step); err != nil {
				t.Fatal(err)
			}
			ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.cert}, VerifiedChains: [][]*x509.Certificate{{f.cert}}}}})
			stream := newTestStream(ctx)
			done := make(chan error, 1)
			go func() { done <- f.service.Connect(stream) }()
			stream.recv <- helloWithoutCapabilities(f.response.NodeId)
			receiveServerFrame(t, stream, done)
			deadline := time.Now().Add(time.Second)
			for {
				stored, err := f.store.TaskByID(context.Background(), task.ID)
				if err == nil && stored.State == "failed" {
					if stored.ErrorCode != tc.errorCode {
						t.Fatalf("task=%+v", stored)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("unsupported task was not failed: %+v err=%v", stored, err)
				}
				time.Sleep(time.Millisecond)
			}
			select {
			case frame := <-stream.sent:
				t.Fatalf("unsupported command was dispatched: %v", frame)
			default:
			}
			close(stream.recv)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if tc.taskType == "risk_repair" {
				audits, err := f.store.ListAuditLogs(context.Background(), domain.AuditFilter{Action: "deployment_risk.repair.result"}, 10, "")
				if err != nil || len(audits.Items) != 1 || audits.Items[0].Outcome != "failed" {
					t.Fatalf("repair result audits=%+v err=%v", audits.Items, err)
				}
			}
		})
	}
}

type fixture struct {
	service  *Service
	store    *sqlstore.Store
	manager  *pki.Manager
	request  *agentv1.EnrollRequest
	response *agentv1.EnrollResponse
	cert     *x509.Certificate
	adminID  string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	db, e := sqlstore.Open(ctx, "sqlite", ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	manager, e := pki.LoadOrCreate(config.PKIConfig{Directory: t.TempDir()})
	if e != nil {
		t.Fatal(e)
	}
	admin := domain.User{ID: uuid.Must(uuid.NewV7()).String(), Username: "admin", PasswordHash: "unused", Status: "active", Role: "admin", CreatedAt: time.Now()}
	if e = db.CreateUser(ctx, admin); e != nil {
		t.Fatal(e)
	}
	_, raw, e := node.New(db).CreateEnrollmentToken(ctx, "client", admin.ID, 10*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		t.Fatal(e)
	}
	req := &agentv1.EnrollRequest{EnrollmentToken: raw, PublicKeyPem: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), Role: agentv1.NodeRole_NODE_ROLE_CLIENT, Hostname: "test-node", AgentVersion: "test"}
	service := NewService(db, manager, events.New(), slog.New(slog.NewTextHandler(io.Discard, nil)), testMaterializer{})
	resp, e := service.Enroll(ctx, req)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.SetNodeManagementMode(ctx, resp.NodeId, "managed", time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(resp.CertificatePem)
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	return &fixture{service: service, store: db, manager: manager, request: req, response: resp, cert: cert, adminID: admin.ID}
}

type testMaterializer struct{}

func (testMaterializer) Materialize(context.Context, string) (ConfigMaterial, error) {
	return ConfigMaterial{SHA256: "abc123", Strategy: "restart", Content: []byte("serverAddr = \"secret.example\"\n")}, nil
}

type testUpgradeMaterializer struct {
	material UpgradeMaterial
	err      error
}

type capturedAlert struct {
	kind, severity, resource, message string
}

type captureAlertSink struct{ alerts []capturedAlert }

func (s *captureAlertSink) Trigger(_ context.Context, kind, severity, resource, message string) {
	s.alerts = append(s.alerts, capturedAlert{kind: kind, severity: severity, resource: resource, message: message})
}

func TestDeploymentRisksAreMappedAndDeduplicated(t *testing.T) {
	sink := &captureAlertSink{}
	service := &Service{alerter: sink}
	service.triggerDeploymentRisks(context.Background(), "node-1", []*agentv1.DeploymentRisk{
		{Kind: agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_ADMIN_API_NON_LOOPBACK},
		{Kind: agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_ADMIN_API_NON_LOOPBACK},
		{Kind: agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_CONFIG_TOKEN_PERMISSIONS},
		{Kind: agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_PROXY_NAME_CONFLICT},
		{Kind: agentv1.DeploymentRiskKind(99)},
	})
	if len(sink.alerts) != 3 {
		t.Fatalf("alerts=%+v", sink.alerts)
	}
	if sink.alerts[0].kind != "admin_api_non_loopback" || sink.alerts[0].severity != "critical" || sink.alerts[0].resource != "node/node-1" {
		t.Fatalf("admin API alert=%+v", sink.alerts[0])
	}
	if sink.alerts[1].kind != "config_token_permissions" || sink.alerts[1].severity != "critical" {
		t.Fatalf("permissions alert=%+v", sink.alerts[1])
	}
	if sink.alerts[2].kind != "proxy_name_conflict" || sink.alerts[2].severity != "warning" {
		t.Fatalf("proxy alert=%+v", sink.alerts[2])
	}
}

func TestNormalizeRepairResultRequiresTypedSuccessfulOutput(t *testing.T) {
	stateValue, code, _, _ := normalizeRepairResult("succeeded", "", "", nil)
	if stateValue != "failed" || code != "INVALID_RESPONSE" {
		t.Fatalf("missing typed output accepted: state=%s code=%s", stateValue, code)
	}
	stateValue, code, _, _ = normalizeRepairResult("succeeded", "", "", &agentv1.RepairDeploymentRiskResult{PrecheckPassed: true, Changed: true, BackupCreated: false})
	if stateValue != "failed" || code != "RECOVERY_FAILED" {
		t.Fatalf("missing backup/rollback accepted: state=%s code=%s", stateValue, code)
	}
	stateValue, code, _, output := normalizeRepairResult("succeeded", "", "", &agentv1.RepairDeploymentRiskResult{PrecheckPassed: true, Changed: true, BackupCreated: true})
	if stateValue != "succeeded" || code != "" || !strings.Contains(output, `"backup_created":true`) {
		t.Fatalf("valid repair rejected: state=%s code=%s output=%s", stateValue, code, output)
	}
}

func (m testUpgradeMaterializer) MaterializeUpgrade(context.Context, string) (UpgradeMaterial, error) {
	return m.material, m.err
}

func TestEnrollCertificateAndTokenReplay(t *testing.T) {
	f := newFixture(t)
	if f.response.CertificateExpiresAtUnixMs <= time.Now().UnixMilli() {
		t.Fatal("certificate is already expired")
	}
	if len(f.cert.URIs) != 1 || f.cert.URIs[0].Path != "/node/"+f.response.NodeId {
		t.Fatalf("certificate identity missing: %v", f.cert.URIs)
	}
	if _, e := f.service.Enroll(context.Background(), f.request); status.Code(e) != codes.PermissionDenied {
		t.Fatalf("replay code=%v err=%v", status.Code(e), e)
	}
}

func TestConnectHeartbeatAndIdentity(t *testing.T) {
	f := newFixture(t)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.cert}, VerifiedChains: [][]*x509.Certificate{{f.cert}}}}})
	stream := newTestStream(ctx)
	done := make(chan error, 1)
	go func() { done <- f.service.Connect(stream) }()
	stream.recv <- hello(f.response.NodeId)
	welcome := receiveServerFrame(t, stream, done)
	sessionID := welcome.GetWelcome().GetSessionId()
	if sessionID == "" {
		t.Fatal("welcome session missing")
	}
	stream.recv <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_Heartbeat{Heartbeat: &agentv1.Heartbeat{SessionId: sessionID, Sequence: 1}}}
	deadline := time.Now().Add(time.Second)
	for {
		n, e := f.store.NodeByID(context.Background(), f.response.NodeId)
		if e == nil && n.Observation != nil && n.Observation.Online && !n.Observation.LastHeartbeat.IsZero() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("heartbeat was not persisted")
		}
		time.Sleep(time.Millisecond)
	}
	close(stream.recv)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	n, e := f.store.NodeByID(context.Background(), f.response.NodeId)
	if e != nil {
		t.Fatal(e)
	}
	if n.Observation.Online {
		t.Fatal("disconnect did not mark node offline")
	}
	bad := newTestStream(ctx)
	bad.recv <- hello(uuid.NewString())
	close(bad.recv)
	if e = f.service.Connect(bad); status.Code(e) != codes.PermissionDenied {
		t.Fatalf("identity mismatch code=%v err=%v", status.Code(e), e)
	}
}

func TestConnectRotatesCertificateForAuthenticatedNode(t *testing.T) {
	f := newFixture(t)
	f.service.now = func() time.Time { return f.cert.NotAfter.Add(-7 * 24 * time.Hour) }
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{f.cert}, VerifiedChains: [][]*x509.Certificate{{f.cert}},
	}}})
	stream := newTestStream(ctx)
	done := make(chan error, 1)
	go func() { done <- f.service.Connect(stream) }()
	stream.recv <- hello(f.response.NodeId)
	if welcome := receiveServerFrame(t, stream, done); welcome.GetWelcome().GetSessionId() == "" {
		t.Fatal("welcome session missing")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"attacker.example"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	requestID := "0123456789abcdef0123456789abcdef"
	stream.recv <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CertificateRotationRequest{CertificateRotationRequest: &agentv1.CertificateRotationRequest{
		RequestId: requestID, CurrentSerial: f.cert.SerialNumber.String(), CsrPem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), CertificateExpiresAtUnixMs: f.cert.NotAfter.UnixMilli(),
	}}}
	response := receiveServerFrame(t, stream, done)
	rotation := response.GetRotateCertificate()
	if rotation == nil || rotation.GetRequestId() != requestID {
		t.Fatalf("unexpected rotation response: %v", response)
	}
	block, _ := pem.Decode(rotation.GetCertificatePem())
	rotated, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.SerialNumber.Cmp(f.cert.SerialNumber) == 0 || len(rotated.DNSNames) != 1 || rotated.DNSNames[0] != f.response.NodeId {
		t.Fatalf("unexpected rotated identity: serial=%s DNS=%v", rotated.SerialNumber, rotated.DNSNames)
	}
	if len(rotated.URIs) != 1 || rotated.URIs[0].String() != "spiffe://frp-admin/client/"+f.response.NodeId {
		t.Fatalf("unexpected rotated URI: %v", rotated.URIs)
	}
	wantKey, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	gotKey, _ := x509.MarshalPKIXPublicKey(rotated.PublicKey)
	if !bytes.Equal(wantKey, gotKey) {
		t.Fatal("rotated certificate does not contain CSR public key")
	}
	close(stream.recv)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCommandFrameCannotMutateAnotherNodesTask(t *testing.T) {
	f := newFixture(t)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.cert}, VerifiedChains: [][]*x509.Certificate{{f.cert}}}}})
	stream := newTestStream(ctx)
	done := make(chan error, 1)
	go func() { done <- f.service.Connect(stream) }()
	stream.recv <- hello(f.response.NodeId)
	receiveServerFrame(t, stream, done)
	now := time.Now().UTC()
	taskID := uuid.Must(uuid.NewV7()).String()
	record := domain.Task{ID: taskID, Type: "inspect", State: "dispatched", NodeID: uuid.NewString(), IdempotencyKey: uuid.NewString(), RequestedBy: "admin", CreatedAt: now, UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.Must(uuid.NewV7()).String(), TaskID: taskID, Name: "inspect", State: "dispatched", CreatedAt: now, UpdatedAt: now}
	if e := f.store.CreateTask(context.Background(), record, step); e != nil {
		t.Fatal(e)
	}
	stream.recv <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CommandAck{CommandAck: &agentv1.CommandAck{CommandId: taskID}}}
	if e := <-done; status.Code(e) != codes.PermissionDenied {
		t.Fatalf("cross-node frame code=%v err=%v", status.Code(e), e)
	}
	got, e := f.store.TaskByID(context.Background(), taskID)
	if e != nil {
		t.Fatal(e)
	}
	if got.State != "dispatched" {
		t.Fatalf("cross-node frame mutated state to %s", got.State)
	}
}

func TestQueuedInspectDispatchesOnReconnect(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC()
	taskID := uuid.Must(uuid.NewV7()).String()
	record := domain.Task{ID: taskID, Type: "inspect", State: "queued", NodeID: f.response.NodeId, IdempotencyKey: uuid.NewString(), RequestedBy: "admin", CreatedAt: now, UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.Must(uuid.NewV7()).String(), TaskID: taskID, Name: "inspect", State: "queued", CreatedAt: now, UpdatedAt: now}
	if e := f.store.CreateTask(context.Background(), record, step); e != nil {
		t.Fatal(e)
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.cert}, VerifiedChains: [][]*x509.Certificate{{f.cert}}}}})
	stream := newTestStream(ctx)
	done := make(chan error, 1)
	go func() { done <- f.service.Connect(stream) }()
	stream.recv <- hello(f.response.NodeId)
	if receiveServerFrame(t, stream, done).GetWelcome() == nil {
		t.Fatal("missing Welcome")
	}
	sent := receiveServerFrame(t, stream, done)
	if sent.GetCommand() == nil || sent.GetCommand().GetCommandId() != taskID {
		t.Fatalf("queued task not dispatched: %v", sent)
	}
	got, e := f.store.TaskByID(context.Background(), taskID)
	if e != nil {
		t.Fatal(e)
	}
	if got.State != "dispatched" {
		t.Fatalf("task state=%s", got.State)
	}
	close(stream.recv)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestQueuedUpgradeDispatchesStructuredCommandOnReconnect(t *testing.T) {
	f := newFixture(t)
	f.service.SetUpgradeMaterializer(testUpgradeMaterializer{material: UpgradeMaterial{Version: "v0.70.0", ArtifactURL: "https://download.example/frp?token=secret", SHA256: strings.Repeat("a", 64)}})
	now := time.Now().UTC()
	planID, taskID := uuid.NewString(), uuid.NewString()
	plan := domain.UpgradePlan{ID: planID, NodeID: f.response.NodeId, Version: "v0.70.0", ArtifactCiphertext: []byte("ciphertext"), ArtifactNonce: []byte("nonce"), ArtifactKeyVersion: "1", SHA256: strings.Repeat("a", 64), State: "queued", TaskID: taskID, CreatedBy: f.adminID, CreatedAt: now, UpdatedAt: now}
	record := domain.Task{ID: taskID, Type: "frp_upgrade", State: "queued", NodeID: f.response.NodeId, IdempotencyKey: uuid.NewString(), RequestedBy: f.adminID, Payload: "{}", UpgradePlanID: &planID, CreatedAt: now, UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.NewString(), TaskID: taskID, Name: "frp_upgrade", State: "queued", Attempt: 1, CreatedAt: now, UpdatedAt: now}
	if err := f.store.CreateUpgradePlanTask(context.Background(), plan, record, step); err != nil {
		t.Fatal(err)
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.cert}, VerifiedChains: [][]*x509.Certificate{{f.cert}}}}})
	stream := newTestStream(ctx)
	done := make(chan error, 1)
	go func() { done <- f.service.Connect(stream) }()
	stream.recv <- hello(f.response.NodeId)
	receiveServerFrame(t, stream, done)
	frame := receiveServerFrame(t, stream, done)
	upgrade := frame.GetCommand().GetUpgradeFrp()
	if upgrade == nil || upgrade.GetVersion() != "v0.70.0" || upgrade.GetArtifactUrl() != "https://download.example/frp?token=secret" || upgrade.GetSha256() != strings.Repeat("a", 64) {
		t.Fatalf("unexpected structured upgrade command: %v", frame)
	}
	close(stream.recv)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeResultPersistsNormalizedSnapshot(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC()
	taskID := uuid.NewString()
	record := domain.Task{ID: taskID, Type: "collect_runtime", State: "queued", NodeID: f.response.NodeId, IdempotencyKey: uuid.NewString(), RequestedBy: f.adminID, Payload: "{}", CreatedAt: now, UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.NewString(), TaskID: taskID, Name: "collect_runtime", State: "queued", Attempt: 1, CreatedAt: now, UpdatedAt: now}
	if err := f.store.CreateTask(context.Background(), record, step); err != nil {
		t.Fatal(err)
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.cert}, VerifiedChains: [][]*x509.Certificate{{f.cert}}}}})
	stream := newTestStream(ctx)
	done := make(chan error, 1)
	go func() { done <- f.service.Connect(stream) }()
	stream.recv <- hello(f.response.NodeId)
	receiveServerFrame(t, stream, done)
	if command := receiveServerFrame(t, stream, done); command.GetCommand().GetCollectRuntime() == nil {
		t.Fatalf("runtime collection was not dispatched: %v", command)
	}
	stream.recv <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CommandAck{CommandAck: &agentv1.CommandAck{CommandId: taskID}}}
	snapshot := &agentv1.RuntimeSnapshot{Role: agentv1.NodeRole_NODE_ROLE_CLIENT, CollectedAtUnixMs: now.UnixMilli(), FrpVersion: "v0.70.0", Proxies: []*agentv1.RuntimeProxy{{Name: "ssh", Type: "tcp", Status: agentv1.RuntimeProxyStatus_RUNTIME_PROXY_STATUS_RUNNING, LocalAddress: "127.0.0.1:22", RemoteAddress: ":6000", Traffic: &agentv1.RuntimeTraffic{BytesIn: 10, BytesOut: 20, CurrentConnections: 1}}}, Clients: []*agentv1.RuntimeClient{{Id: "client-1", Address: "10.0.0.1", ConnectedAtUnixMs: now.Add(-time.Minute).UnixMilli()}}}
	stream.recv <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CommandResult{CommandResult: &agentv1.CommandResult{CommandId: taskID, Status: agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED, Output: &agentv1.CommandResult_Runtime{Runtime: &agentv1.RuntimeResult{Snapshot: snapshot}}}}}
	deadline := time.Now().Add(time.Second)
	for {
		stored, err := f.store.RuntimeSnapshotByNode(context.Background(), f.response.NodeId)
		if err == nil && len(stored.Proxies) == 1 && len(stored.Clients) == 1 {
			if stored.Proxies[0].Name != "ssh" || stored.Proxies[0].Traffic.BytesOut != 20 {
				t.Fatalf("runtime snapshot data mismatch: %+v", stored)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("runtime snapshot not persisted: %+v err=%v", stored, err)
		}
		time.Sleep(time.Millisecond)
	}
	close(stream.recv)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeSnapshotRejectsFutureAgentClock(t *testing.T) {
	now := time.Now().UTC()
	_, err := runtimeFromProto(&agentv1.RuntimeSnapshot{Role: agentv1.NodeRole_NODE_ROLE_CLIENT, CollectedAtUnixMs: now.Add(6 * time.Minute).UnixMilli()}, uuid.NewString(), now)
	if err == nil {
		t.Fatal("runtime snapshot with a far-future Agent timestamp was accepted")
	}
}

func TestQueuedConfigApplyDispatchAndRevisionCAS(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC()
	revisionID := uuid.Must(uuid.NewV7()).String()
	if e := f.store.CreateConfigRevision(context.Background(), domain.ConfigRevision{ID: revisionID, NodeID: f.response.NodeId, Version: 1, EncryptedContent: []byte("cipher"), Nonce: []byte("nonce"), SHA256: "abc123", Strategy: "restart", CreatedBy: f.adminID, CreatedAt: now}); e != nil {
		t.Fatal(e)
	}
	taskID := uuid.Must(uuid.NewV7()).String()
	record := domain.Task{ID: taskID, Type: "config_apply", State: "queued", NodeID: f.response.NodeId, IdempotencyKey: uuid.NewString(), RequestedBy: f.adminID, Payload: "{}", ConfigRevisionID: &revisionID, CreatedAt: now, UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.Must(uuid.NewV7()).String(), TaskID: taskID, Name: "config_apply", State: "queued", Attempt: 1, CreatedAt: now, UpdatedAt: now}
	if e := f.store.CreateTask(context.Background(), record, step); e != nil {
		t.Fatal(e)
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.cert}, VerifiedChains: [][]*x509.Certificate{{f.cert}}}}})
	stream := newTestStream(ctx)
	done := make(chan error, 1)
	go func() { done <- f.service.Connect(stream) }()
	stream.recv <- hello(f.response.NodeId)
	receiveServerFrame(t, stream, done)
	command := receiveServerFrame(t, stream, done)
	apply := command.GetCommand().GetApplyConfig()
	if apply == nil || apply.GetRevision() != revisionID || !bytes.Contains(apply.GetContent(), []byte("secret.example")) {
		t.Fatalf("bad apply command: %v", command)
	}
	stream.recv <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CommandResult{CommandResult: &agentv1.CommandResult{CommandId: taskID, Status: agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED}}}
	deadline := time.Now().Add(time.Second)
	for {
		nodeRecord, e := f.store.NodeByID(context.Background(), f.response.NodeId)
		if e == nil && nodeRecord.DesiredRevisionID != nil && *nodeRecord.DesiredRevisionID == revisionID && nodeRecord.Observation.ObservedRevisionID != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("revision not advanced: %+v %v", nodeRecord, e)
		}
		time.Sleep(time.Millisecond)
	}
	if e := f.service.Dispatch(context.Background(), Command{ID: uuid.NewString(), NodeID: f.response.NodeId, Type: "config_rollback", Revision: revisionID, SHA256: "abc123", Strategy: "restart", Payload: []byte("serverAddr = \"current-secret\"\n")}); e != nil {
		t.Fatal(e)
	}
	rollbackCommand := receiveServerFrame(t, stream, done)
	if rollbackCommand.GetCommand().GetApplyConfig() == nil || rollbackCommand.GetCommand().GetRollbackConfig() != nil {
		t.Fatalf("control-plane rollback did not use materialized ApplyConfig: %v", rollbackCommand)
	}
	close(stream.recv)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func TestCommandDiagnosticSecretIsNotPersisted(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC()
	revisionID := uuid.Must(uuid.NewV7()).String()
	if err := f.store.CreateConfigRevision(context.Background(), domain.ConfigRevision{ID: revisionID, NodeID: f.response.NodeId, Version: 1, EncryptedContent: []byte("cipher"), Nonce: []byte("nonce"), SHA256: "abc123", Strategy: "restart", CreatedBy: f.adminID, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	taskID := uuid.Must(uuid.NewV7()).String()
	record := domain.Task{ID: taskID, Type: "config_apply", State: "queued", NodeID: f.response.NodeId, IdempotencyKey: uuid.NewString(), RequestedBy: f.adminID, Payload: "{}", ConfigRevisionID: &revisionID, CreatedAt: now, UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.Must(uuid.NewV7()).String(), TaskID: taskID, Name: "config_apply", State: "queued", Attempt: 1, CreatedAt: now, UpdatedAt: now}
	if err := f.store.CreateTask(context.Background(), record, step); err != nil {
		t.Fatal(err)
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.cert}, VerifiedChains: [][]*x509.Certificate{{f.cert}}}}})
	stream := newTestStream(ctx)
	done := make(chan error, 1)
	go func() { done <- f.service.Connect(stream) }()
	stream.recv <- hello(f.response.NodeId)
	receiveServerFrame(t, stream, done)
	receiveServerFrame(t, stream, done)
	secret := "token=top-secret"
	stream.recv <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CommandResult{CommandResult: &agentv1.CommandResult{
		CommandId: taskID, Status: agentv1.CommandStatus_COMMAND_STATUS_FAILED,
		ErrorCode: agentv1.ErrorCode_ERROR_CODE_VERIFY_FAILED, Diagnostic: "frp verify output: " + secret,
	}}}
	deadline := time.Now().Add(time.Second)
	for {
		got, err := f.store.TaskByID(context.Background(), taskID)
		if err == nil && got.State == "failed" {
			serialized := got.ErrorMessage
			for _, item := range got.Steps {
				serialized += item.Output
			}
			if strings.Contains(serialized, secret) || got.ErrorMessage != "candidate configuration verification failed" {
				t.Fatalf("unsafe persisted task=%+v", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("failed result was not persisted: task=%+v err=%v", got, err)
		}
		time.Sleep(time.Millisecond)
	}
	close(stream.recv)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSupersededSessionCannotUpdateObservation(t *testing.T) {
	f := newFixture(t)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.cert}, VerifiedChains: [][]*x509.Certificate{{f.cert}}}}})
	first, second := newTestStream(ctx), newTestStream(ctx)
	done1, done2 := make(chan error, 1), make(chan error, 1)
	go func() { done1 <- f.service.Connect(first) }()
	first.recv <- hello(f.response.NodeId)
	welcome1 := receiveServerFrame(t, first, done1)
	go func() { done2 <- f.service.Connect(second) }()
	second.recv <- hello(f.response.NodeId)
	welcome2 := receiveServerFrame(t, second, done2)
	first.recv <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_Heartbeat{Heartbeat: &agentv1.Heartbeat{SessionId: welcome1.GetWelcome().GetSessionId()}}}
	if e := <-done1; status.Code(e) != codes.Aborted {
		t.Fatalf("old session code=%v err=%v", status.Code(e), e)
	}
	second.recv <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_Heartbeat{Heartbeat: &agentv1.Heartbeat{SessionId: welcome2.GetWelcome().GetSessionId()}}}
	close(second.recv)
	if e := <-done2; e != nil {
		t.Fatal(e)
	}
}

func TestInspectDispatchAndResultPersisted(t *testing.T) {
	f := newFixture(t)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.cert}, VerifiedChains: [][]*x509.Certificate{{f.cert}}}}})
	stream := newTestStream(ctx)
	done := make(chan error, 1)
	go func() { done <- f.service.Connect(stream) }()
	stream.recv <- hello(f.response.NodeId)
	welcome := receiveServerFrame(t, stream, done)
	if welcome.GetWelcome() == nil {
		t.Fatal("missing welcome")
	}
	now := time.Now().UTC()
	taskID := uuid.Must(uuid.NewV7()).String()
	record := domain.Task{ID: taskID, Type: "inspect", State: "dispatched", NodeID: f.response.NodeId, IdempotencyKey: uuid.NewString(), RequestedBy: "admin", CreatedAt: now, UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.Must(uuid.NewV7()).String(), TaskID: taskID, Name: "inspect", State: "dispatched", CreatedAt: now, UpdatedAt: now}
	if e := f.store.CreateTask(context.Background(), record, step); e != nil {
		t.Fatal(e)
	}
	if e := f.service.Dispatch(context.Background(), Command{ID: taskID, NodeID: f.response.NodeId, Type: "inspect"}); e != nil {
		t.Fatal(e)
	}
	sent := receiveServerFrame(t, stream, done)
	if sent.GetCommand() == nil || sent.GetCommand().GetInspect() == nil {
		t.Fatalf("unexpected command: %v", sent)
	}
	stream.recv <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CommandAck{CommandAck: &agentv1.CommandAck{CommandId: taskID}}}
	stream.recv <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CommandProgress{CommandProgress: &agentv1.CommandProgress{CommandId: taskID, Percent: 50, Stage: "collecting"}}}
	stream.recv <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CommandResult{CommandResult: &agentv1.CommandResult{CommandId: taskID, Status: agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED, Output: &agentv1.CommandResult_Inspect{Inspect: &agentv1.InspectResult{Inventory: &agentv1.Inventory{FrpVersion: "v0.70.1", Service: &agentv1.ServiceStatus{State: agentv1.ServiceState_SERVICE_STATE_ACTIVE}}}}}}}
	deadline := time.Now().Add(time.Second)
	for {
		got, e := f.store.TaskByID(context.Background(), taskID)
		if e == nil && got.State == "succeeded" {
			if len(got.Steps) != 1 || got.Steps[0].State != "succeeded" {
				t.Fatalf("unexpected steps: %+v", got.Steps)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("task result not persisted: %+v %v", got, e)
		}
		time.Sleep(time.Millisecond)
	}
	stream.recv <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CommandAck{CommandAck: &agentv1.CommandAck{CommandId: taskID}}}
	time.Sleep(10 * time.Millisecond)
	after, e := f.store.TaskByID(context.Background(), taskID)
	if e != nil {
		t.Fatal(e)
	}
	if after.State != "succeeded" {
		t.Fatalf("late Ack regressed task to %s", after.State)
	}
	close(stream.recv)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func TestStructuredServiceAndCancelFrames(t *testing.T) {
	f := newFixture(t)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.cert}, VerifiedChains: [][]*x509.Certificate{{f.cert}}}}})
	stream := newTestStream(ctx)
	done := make(chan error, 1)
	go func() { done <- f.service.Connect(stream) }()
	stream.recv <- hello(f.response.NodeId)
	receiveServerFrame(t, stream, done)
	id := uuid.NewString()
	if err := f.service.Dispatch(context.Background(), Command{ID: id, NodeID: f.response.NodeId, Type: "service_restart"}); err != nil {
		t.Fatal(err)
	}
	frame := receiveServerFrame(t, stream, done)
	if frame.GetCommand().GetService().GetAction() != agentv1.ServiceAction_SERVICE_ACTION_RESTART {
		t.Fatalf("unexpected service frame: %v", frame)
	}
	if err := f.service.Cancel(context.Background(), f.response.NodeId, id, "operator request"); err != nil {
		t.Fatal(err)
	}
	cancel := receiveServerFrame(t, stream, done)
	if cancel.GetCancelCommand().GetCommandId() != id {
		t.Fatalf("unexpected cancel frame: %v", cancel)
	}
	close(stream.recv)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestExpiredTaskRejectsLateAgentResult(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC()
	expires := now.Add(-time.Second)
	id := uuid.NewString()
	record := domain.Task{ID: id, Type: "inspect", State: "running", NodeID: f.response.NodeId, IdempotencyKey: uuid.NewString(), RequestedBy: f.adminID, ExpiresAt: &expires, CreatedAt: now.Add(-time.Minute), UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.NewString(), TaskID: id, Name: "inspect", State: "running", CreatedAt: now, UpdatedAt: now}
	if err := f.store.CreateTask(context.Background(), record, step); err != nil {
		t.Fatal(err)
	}
	if expired, err := f.store.ExpireTasks(context.Background(), now, 10); err != nil || len(expired) != 1 {
		t.Fatalf("expired=%d err=%v", len(expired), err)
	}
	if err := f.store.UpdateTask(context.Background(), id, "succeeded", "", "", "succeeded", "", now.Add(time.Second)); err == nil {
		t.Fatal("late result overwrote timeout terminal state")
	}
	got, err := f.store.TaskByID(context.Background(), id)
	if err != nil || got.State != "failed" || got.ErrorCode != "TIMEOUT" {
		t.Fatalf("task=%+v err=%v", got, err)
	}
}

func TestLateNonConfigRepairResultIsAuditedAndReconciledOnce(t *testing.T) {
	f := newFixture(t)
	sink := &captureAlertSink{}
	f.service.alerter = sink
	now := time.Now().UTC()
	finding := domain.DeploymentRiskObservation{Kind: "config_token_permissions", Severity: "critical", Evidence: "redacted", Confidence: "high", RuleVersion: "1", ResourceFingerprint: strings.Repeat("a", 64)}
	if err := f.store.ReconcileDeploymentRisks(context.Background(), f.response.NodeId, "", "pass", "", []domain.DeploymentRiskObservation{finding}, []string{finding.Kind}, now); err != nil {
		t.Fatal(err)
	}
	expires := now.Add(-time.Second)
	task := domain.Task{ID: uuid.NewString(), Type: "risk_repair", State: "running", NodeID: f.response.NodeId, IdempotencyKey: uuid.NewString(), RequestedBy: f.adminID, Payload: `{"FindingID":"finding-1","Kind":"config_token_permissions","Action":"restrict_config_permissions"}`, ExpiresAt: &expires, CreatedAt: now.Add(-time.Minute), UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.NewString(), TaskID: task.ID, Name: "risk_repair", State: "running", Attempt: 1, CreatedAt: now, UpdatedAt: now}
	if err := f.store.CreateTask(context.Background(), task, step); err != nil {
		t.Fatal(err)
	}
	if expired, err := f.store.ExpireTasks(context.Background(), now, 10); err != nil || len(expired) != 1 {
		t.Fatalf("expired=%+v err=%v", expired, err)
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.cert}, VerifiedChains: [][]*x509.Certificate{{f.cert}}}}})
	stream := newTestStream(ctx)
	done := make(chan error, 1)
	go func() { done <- f.service.Connect(stream) }()
	stream.recv <- hello(f.response.NodeId)
	receiveServerFrame(t, stream, done)
	inventory := &agentv1.Inventory{DeploymentRiskCompletedKinds: []agentv1.DeploymentRiskKind{agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_CONFIG_TOKEN_PERMISSIONS}}
	result := &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CommandResult{CommandResult: &agentv1.CommandResult{CommandId: task.ID, Status: agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED, Output: &agentv1.CommandResult_RepairDeploymentRisk{RepairDeploymentRisk: &agentv1.RepairDeploymentRiskResult{PrecheckPassed: true, Changed: true, BackupCreated: true, Inventory: inventory}}}}}
	stream.recv <- result
	stream.recv <- result
	close(stream.recv)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	page, err := f.store.ListDeploymentRisks(context.Background(), domain.DeploymentRiskFilter{NodeID: f.response.NodeId}, 10, "")
	if err != nil || len(page.Items) != 1 || page.Items[0].State != "pending_confirmation" || page.Items[0].MissedScans != 1 {
		t.Fatalf("late repair reconciliation=%+v err=%v", page.Items, err)
	}
	audits, err := f.store.ListAuditLogs(context.Background(), domain.AuditFilter{Action: "deployment_risk.repair.result"}, 10, "")
	if err != nil || len(audits.Items) != 1 || audits.Items[0].Outcome != "late_applied" {
		t.Fatalf("late repair audit=%+v err=%v", audits.Items, err)
	}
	if len(sink.alerts) != 1 || sink.alerts[0].kind != "late_repair_applied" || sink.alerts[0].severity != "critical" {
		t.Fatalf("late repair alerts=%+v", sink.alerts)
	}
}

func TestGRPCTLSAllowsEnrollButRequiresCertificateForConnect(t *testing.T) {
	f := newFixture(t)
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(f.manager.TLSConfig())))
	agentv1.RegisterAgentControlServiceServer(server, f.service)
	go server.Serve(listener)
	t.Cleanup(func() { server.Stop(); listener.Close() })
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(f.manager.CAPEM()) {
		t.Fatal("load CA")
	}
	dial := func(certificates []tls.Certificate) *grpc.ClientConn {
		conn, e := grpc.NewClient("passthrough:///agent", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: pool, Certificates: certificates})))
		if e != nil {
			t.Fatal(e)
		}
		return conn
	}
	noCert := dial(nil)
	client := agentv1.NewAgentControlServiceClient(noCert)
	stream, e := client.Connect(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	_ = stream.Send(hello(f.response.NodeId))
	if _, e = stream.Recv(); status.Code(e) != codes.Unauthenticated {
		t.Fatalf("Connect without certificate code=%v err=%v", status.Code(e), e)
	}
	_, raw, e := node.New(f.store).CreateEnrollmentToken(context.Background(), "client", f.adminID, 10*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		t.Fatal(e)
	}
	enrolled, e := client.Enroll(context.Background(), &agentv1.EnrollRequest{EnrollmentToken: raw, PublicKeyPem: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), Role: agentv1.NodeRole_NODE_ROLE_CLIENT, Hostname: "grpc-node"})
	if e != nil {
		t.Fatal(e)
	}
	noCert.Close()
	block, _ := pem.Decode(enrolled.CertificatePem)
	nodeCert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	withCert := dial([]tls.Certificate{{Certificate: [][]byte{nodeCert.Raw}, PrivateKey: priv, Leaf: nodeCert}})
	defer withCert.Close()
	secure := agentv1.NewAgentControlServiceClient(withCert)
	connected, e := secure.Connect(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = connected.Send(hello(enrolled.NodeId)); e != nil {
		t.Fatal(e)
	}
	welcome, e := connected.Recv()
	if e != nil {
		t.Fatal(e)
	}
	if welcome.GetWelcome().GetSessionId() == "" {
		t.Fatal("mTLS Connect did not receive Welcome")
	}
	_ = connected.CloseSend()
}

func hello(nodeID string) *agentv1.AgentToServer {
	message := helloWithoutCapabilities(nodeID)
	message.GetHello().Capabilities = []string{"inspect", "service.status", "service.start", "service.stop", "service.restart", "config.apply", "config.rollback", "frp.upgrade", "runtime.collect", "certificate.rotate", "risk.scan", "risk.repair.config_permissions", "risk.repair.admin_loopback"}
	return message
}

func helloWithoutCapabilities(nodeID string) *agentv1.AgentToServer {
	return &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_Hello{Hello: &agentv1.Hello{NodeId: nodeID, Role: agentv1.NodeRole_NODE_ROLE_CLIENT, AgentVersion: "v1", FrpVersion: "v0.70.1", ProtocolVersion: 1}}}
}

type testStream struct {
	ctx  context.Context
	recv chan *agentv1.AgentToServer
	sent chan *agentv1.ServerToAgent
}

func newTestStream(ctx context.Context) *testStream {
	return &testStream{ctx: ctx, recv: make(chan *agentv1.AgentToServer, 8), sent: make(chan *agentv1.ServerToAgent, 8)}
}

func receiveServerFrame(t *testing.T, stream *testStream, done <-chan error) *agentv1.ServerToAgent {
	t.Helper()
	select {
	case frame := <-stream.sent:
		return frame
	case err := <-done:
		t.Fatalf("Connect returned before sending the expected frame: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Server frame")
	}
	return nil
}

func (s *testStream) Send(v *agentv1.ServerToAgent) error { s.sent <- v; return nil }
func (s *testStream) Recv() (*agentv1.AgentToServer, error) {
	v, ok := <-s.recv
	if !ok {
		return nil, io.EOF
	}
	return v, nil
}
func (s *testStream) SetHeader(metadata.MD) error  { return nil }
func (s *testStream) SendHeader(metadata.MD) error { return nil }
func (s *testStream) SetTrailer(metadata.MD)       {}
func (s *testStream) Context() context.Context     { return s.ctx }
func (s *testStream) SendMsg(any) error            { return nil }
func (s *testStream) RecvMsg(any) error            { return nil }
