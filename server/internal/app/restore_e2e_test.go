package app

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/config"
	"github.com/frp-admin/frp-admin/server/internal/configcrypto"
	"github.com/frp-admin/frp-admin/server/internal/configuration"
	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/events"
	"github.com/frp-admin/frp-admin/server/internal/pki"
	"github.com/frp-admin/frp-admin/server/internal/secretmgr"
	"github.com/frp-admin/frp-admin/server/internal/store/sqlstore"
	"github.com/frp-admin/frp-admin/server/internal/task"
	"github.com/frp-admin/frp-admin/server/internal/upgrade"
	"github.com/google/uuid"
)

func TestKeyRingBackupRestoreMaterialization(t *testing.T) {
	if os.Getenv("FRP_ADMIN_RESTORE_E2E") != "1" {
		t.Skip("set FRP_ADMIN_RESTORE_E2E=1 through deploy/ops/test.sh")
	}
	_, filename, _, _ := runtime.Caller(0)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "../../.."))
	dir := t.TempDir()
	sourceDir, restoredDir := filepath.Join(dir, "source"), filepath.Join(dir, "restored")
	for _, path := range []string{sourceDir, restoredDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	oldKey, newKey := filepath.Join(sourceDir, "old.key"), filepath.Join(sourceDir, "new.key")
	for _, path := range []string{oldKey, newKey} {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, key, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pkiDir := filepath.Join(sourceDir, "pki")
	generateRestorePKI(t, pkiDir, dir)
	if _, err := pki.LoadOrCreate(config.PKIConfig{Directory: pkiDir, ServerNames: []string{"localhost"}}); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	sourceDB := filepath.Join(sourceDir, "control.db")
	db, err := sqlstore.Open(ctx, "sqlite", sourceDB)
	if err != nil {
		t.Fatal(err)
	}
	now, userID, nodeID := time.Now().UTC(), uuid.NewString(), uuid.NewString()
	if err = db.CreateUser(ctx, domain.User{ID: userID, Username: "restore-admin", PasswordHash: "unused", Status: "active", Role: "admin", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	token := domain.EnrollmentToken{ID: uuid.NewString(), Role: "client", TokenHash: uuid.NewString(), CreatedBy: userID, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err = db.CreateEnrollmentToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err = db.ConsumeEnrollmentTokenAndCreateNode(ctx, token.TokenHash, token.Role, domain.Node{ID: nodeID, Name: "restore-node", Role: "client", Labels: "{}", ManagementMode: "managed", CreatedAt: now, UpdatedAt: now}, now); err != nil {
		t.Fatal(err)
	}
	if err = db.UpsertObservation(ctx, domain.NodeObservation{NodeID: nodeID, Online: true, Capabilities: `["frp.upgrade"]`, LastHeartbeat: now}); err != nil {
		t.Fatal(err)
	}
	oldRing, err := configcrypto.LoadKeyRing(oldKey, "old", map[string]string{"old": oldKey})
	if err != nil {
		t.Fatal(err)
	}
	oldSecrets := secretmgr.New(db, oldRing)
	if _, err = oldSecrets.Create(ctx, "RESTORE_TOKEN", "old-key-secret", userID); err != nil {
		t.Fatal(err)
	}
	tasks := task.New(db, nil, events.New())
	oldUpgrades := upgrade.New(db, nil, tasks, events.New(), time.Hour, oldRing)
	createdUpgrade, err := oldUpgrades.Create(ctx, nodeID, "v0.70.0", "https://download.example/frp?token=old-key-url", strings.Repeat("a", 64), userID, "restore-upgrade")
	if err != nil {
		t.Fatal(err)
	}
	rotatedRing, err := configcrypto.LoadKeyRing(newKey, "new", map[string]string{"old": oldKey, "new": newKey})
	if err != nil {
		t.Fatal(err)
	}
	rotatedSecrets := secretmgr.New(db, rotatedRing)
	configs := configuration.New(db, rotatedRing, events.New(), rotatedSecrets)
	revision, err := configs.Create(ctx, nodeID, userID, "restart", []byte("serverAddr = \"example.test\"\n[auth]\ntoken = \"${secret:RESTORE_TOKEN}\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(dir, "backup.tar")
	runRestoreCommand(t, repoRoot, "deploy/ops/backup.sh", "--driver", "sqlite", "--sqlite-path", sourceDB, "--master-key", newKey, "--key-version", "old="+oldKey, "--key-version", "new="+newKey, "--pki-dir", pkiDir, "--output", archive)
	restoredDB, restoredMaster, restoredPKI, restoredKeys := filepath.Join(restoredDir, "control.db"), filepath.Join(restoredDir, "master.key"), filepath.Join(restoredDir, "pki"), filepath.Join(restoredDir, "keyring")
	runRestoreCommand(t, repoRoot, "deploy/ops/restore.sh", "--archive", archive, "--sqlite-target", restoredDB, "--master-key-target", restoredMaster, "--pki-target", restoredPKI, "--keyring-target", restoredKeys)

	restoredStore, err := sqlstore.Open(ctx, "sqlite", restoredDB)
	if err != nil {
		t.Fatal(err)
	}
	defer restoredStore.Close()
	restoredRing, err := configcrypto.LoadKeyRing(restoredMaster, "new", map[string]string{"old": filepath.Join(restoredKeys, "old.key"), "new": filepath.Join(restoredKeys, "new.key")})
	if err != nil {
		t.Fatal(err)
	}
	restoredSecrets := secretmgr.New(restoredStore, restoredRing)
	listed, err := restoredSecrets.List(ctx, 10, "")
	if err != nil || len(listed.Items) != 1 || len(listed.Items[0].Ciphertext) != 0 || len(listed.Items[0].Nonce) != 0 {
		t.Fatalf("restored Secret metadata leaked encrypted material: %+v err=%v", listed, err)
	}
	if value, err := restoredSecrets.Resolve(ctx, "RESTORE_TOKEN"); err != nil || value != "old-key-secret" {
		t.Fatalf("old Secret did not decrypt after restore: value=%q err=%v", value, err)
	}
	restoredConfigs := configuration.New(restoredStore, restoredRing, events.New(), restoredSecrets)
	material, err := restoredConfigs.Materialize(ctx, revision.ID)
	if err != nil || !strings.Contains(string(material.Content), "old-key-secret") || strings.Contains(string(material.Content), "${secret:") {
		t.Fatalf("old Secret did not materialize into restored config: %q err=%v", material.Content, err)
	}
	restoredUpgrades := upgrade.New(restoredStore, nil, task.New(restoredStore, nil, events.New()), events.New(), time.Hour, restoredRing)
	upgradeMaterial, err := restoredUpgrades.MaterializeUpgrade(ctx, createdUpgrade.Plan.ID)
	if err != nil || upgradeMaterial.ArtifactURL != "https://download.example/frp?token=old-key-url" {
		t.Fatalf("old upgrade URL did not materialize after restore: %+v err=%v", upgradeMaterial, err)
	}

	missingOldConfig := config.Default()
	missingOldConfig.Database.DSN = restoredDB
	missingOldConfig.PKI.Directory = restoredPKI
	missingOldConfig.MasterKey.File = restoredMaster
	missingOldConfig.MasterKey.CurrentVersion = "new"
	missingOldConfig.MasterKey.KeyFiles = map[string]string{"new": filepath.Join(restoredKeys, "new.key")}
	if started, err := New(ctx, missingOldConfig, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		_ = started.Shutdown(context.Background())
		t.Fatal("Server started without a historical key referenced by encrypted data")
	}
	missingRing, err := configcrypto.LoadKeyRing(restoredMaster, "new", missingOldConfig.MasterKey.KeyFiles)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = secretmgr.New(restoredStore, missingRing).Resolve(ctx, "RESTORE_TOKEN"); err == nil {
		t.Fatal("old Secret decrypted without its historical key")
	}
	if _, err = upgrade.New(restoredStore, nil, task.New(restoredStore, nil, events.New()), events.New(), time.Hour, missingRing).MaterializeUpgrade(ctx, createdUpgrade.Plan.ID); err == nil {
		t.Fatal("old upgrade URL materialized without its historical key")
	}
}

func generateRestorePKI(t *testing.T, pkiDir, workDir string) {
	t.Helper()
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		command := exec.Command("openssl", args...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("openssl %s failed: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
	caKey, caCert := filepath.Join(pkiDir, "ca.key"), filepath.Join(pkiDir, "ca.crt")
	serverKey, serverCert := filepath.Join(pkiDir, "server.key"), filepath.Join(pkiDir, "server.crt")
	csr, ext := filepath.Join(workDir, "server.csr"), filepath.Join(workDir, "server.ext")
	run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-pkeyopt", "ec_param_enc:named_curve", "-out", caKey)
	run("req", "-x509", "-new", "-key", caKey, "-sha256", "-days", "2", "-subj", "/CN=frp-admin restore test CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign,digitalSignature", "-out", caCert)
	run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-pkeyopt", "ec_param_enc:named_curve", "-out", serverKey)
	run("req", "-new", "-key", serverKey, "-subj", "/CN=frp-admin-server", "-out", csr)
	if err := os.WriteFile(ext, []byte("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("x509", "-req", "-in", csr, "-CA", caCert, "-CAkey", caKey, "-CAcreateserial", "-days", "2", "-sha256", "-extfile", ext, "-out", serverCert)
	for _, path := range []string{caKey, caCert, serverKey, serverCert} {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func runRestoreCommand(t *testing.T, repoRoot, name string, args ...string) {
	t.Helper()
	command := exec.Command(filepath.Join(repoRoot, name), args...)
	command.Dir = repoRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s failed: %v\n%s", name, err, output)
	}
}
