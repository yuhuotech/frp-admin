package upgrade

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/configcrypto"
	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/events"
	"github.com/frp-admin/frp-admin/server/internal/store"
	"github.com/frp-admin/frp-admin/server/internal/store/sqlstore"
	"github.com/frp-admin/frp-admin/server/internal/task"
	"github.com/google/uuid"
)

type upgradeFixture struct {
	store  *sqlstore.Store
	nodeID string
	userID string
}

func newUpgradeFixture(t *testing.T) upgradeFixture {
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
	node := domain.Node{ID: nodeID, Name: "managed-node", Role: "client", Labels: "{}", ManagementMode: "managed", CreatedAt: now, UpdatedAt: now}
	if err = db.ConsumeEnrollmentTokenAndCreateNode(ctx, token.TokenHash, token.Role, node, now); err != nil {
		t.Fatal(err)
	}
	if err = db.UpsertObservation(ctx, domain.NodeObservation{NodeID: nodeID, Online: true, Capabilities: `["frp.upgrade","inspect","runtime.collect"]`, LastHeartbeat: now}); err != nil {
		t.Fatal(err)
	}
	return upgradeFixture{store: db, nodeID: nodeID, userID: userID}
}

func addManagedNode(t *testing.T, f upgradeFixture) string {
	t.Helper()
	now := time.Now().UTC()
	token := domain.EnrollmentToken{ID: uuid.NewString(), Role: "client", TokenHash: uuid.NewString(), CreatedBy: f.userID, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := f.store.CreateEnrollmentToken(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	nodeID := uuid.NewString()
	node := domain.Node{ID: nodeID, Name: "race-" + nodeID, Role: "client", Labels: "{}", ManagementMode: "managed", CreatedAt: now, UpdatedAt: now}
	if err := f.store.ConsumeEnrollmentTokenAndCreateNode(context.Background(), token.TokenHash, token.Role, node, now); err != nil {
		t.Fatal(err)
	}
	if err := f.store.UpsertObservation(context.Background(), domain.NodeObservation{NodeID: nodeID, Online: true, Capabilities: `["frp.upgrade"]`, LastHeartbeat: now}); err != nil {
		t.Fatal(err)
	}
	return nodeID
}

func TestCreateEncryptsArtifactAndValidatesInputs(t *testing.T) {
	f := newUpgradeFixture(t)
	cipher, err := configcrypto.LoadOrCreate(filepath.Join(t.TempDir(), "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	tasks := task.New(f.store, nil, events.New())
	service := New(f.store, nil, tasks, events.New(), time.Minute, cipher)
	sha := strings.Repeat("a", 64)
	for name, input := range map[string]struct{ version, url, sha, key string }{
		"version":  {"latest", "https://download.example/frp", sha, "key-version"},
		"http":     {"v0.70.0", "http://download.example/frp", sha, "key-http"},
		"userinfo": {"v0.70.0", "https://user:pass@download.example/frp", sha, "key-userinfo"},
		"fragment": {"v0.70.0", "https://download.example/frp#secret", sha, "key-fragment"},
		"sha":      {"v0.70.0", "https://download.example/frp", "abcd", "key-sha"},
		"key":      {"v0.70.0", "https://download.example/frp", sha, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.Create(context.Background(), f.nodeID, input.version, input.url, input.sha, f.userID, input.key); err == nil {
				t.Fatal("invalid upgrade input accepted")
			}
		})
	}
	artifact := "https://download.example/frp.tar.gz?X-Amz-Signature=presigned-secret"
	created, err := service.Create(context.Background(), f.nodeID, "v0.70.0", artifact, sha, f.userID, "valid-key")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := f.store.UpgradePlanByID(context.Background(), created.Plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ArtifactURL != "" || bytes.Contains(stored.ArtifactCiphertext, []byte("presigned-secret")) || created.Plan.ArtifactURL != artifact {
		t.Fatal("artifact URL encryption or transient materialization boundary failed")
	}
	material, err := service.MaterializeUpgrade(context.Background(), created.Plan.ID)
	if err != nil || material.ArtifactURL != artifact || material.SHA256 != sha {
		t.Fatalf("materialized=%+v err=%v", material, err)
	}
	if expired, err := f.store.ExpireTasks(context.Background(), time.Now().Add(2*time.Minute), 10); err != nil || len(expired) != 1 {
		t.Fatalf("expire upgrade task: tasks=%d err=%v", len(expired), err)
	}
	if err := f.store.UpdateTask(context.Background(), created.Task.ID, "succeeded", "", "", "succeeded", "", time.Now().Add(3*time.Minute)); err == nil {
		t.Fatal("late upgrade result overwrote timeout terminal state")
	}
	failedPlan, err := f.store.UpgradePlanByID(context.Background(), created.Plan.ID)
	if err != nil || failedPlan.State != "failed" {
		t.Fatalf("upgrade plan did not mirror timeout: state=%s err=%v", failedPlan.State, err)
	}
}

func TestCreateCapabilityGateAndIdempotencyReplay(t *testing.T) {
	f := newUpgradeFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := f.store.UpsertObservation(ctx, domain.NodeObservation{NodeID: f.nodeID, Online: true, Capabilities: `[]`, LastHeartbeat: now}); err != nil {
		t.Fatal(err)
	}
	cipher, err := configcrypto.LoadOrCreate(filepath.Join(t.TempDir(), "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	service := New(f.store, nil, task.New(f.store, nil, events.New()), events.New(), time.Minute, cipher)
	sha := strings.Repeat("e", 64)
	artifact := "https://download.example/frp.tar.gz?token=secret"
	if _, err = service.Create(ctx, f.nodeID, "v0.70.0", artifact, sha, f.userID, "upgrade-replay"); !errors.Is(err, store.ErrCapabilityUnavailable) {
		t.Fatalf("upgrade without capability got %v", err)
	}
	page, err := f.store.ListUpgradePlans(ctx, 10, "", f.nodeID, "")
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("capability failure created a plan: count=%d err=%v", len(page.Items), err)
	}
	if err = f.store.UpsertObservation(ctx, domain.NodeObservation{NodeID: f.nodeID, Online: true, Capabilities: `["frp.upgrade"]`, LastHeartbeat: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(ctx, f.nodeID, "v0.70.0", artifact, sha, f.userID, "upgrade-replay")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.UpsertObservation(ctx, domain.NodeObservation{NodeID: f.nodeID, Online: true, Capabilities: `[]`, LastHeartbeat: now.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	replayed, err := service.Create(ctx, f.nodeID, "v0.70.0", artifact, sha, f.userID, "upgrade-replay")
	if err != nil || replayed.Task.ID != created.Task.ID || replayed.Plan.ID != created.Plan.ID {
		t.Fatalf("upgrade replay after capability removal: task=%s plan=%s err=%v", replayed.Task.ID, replayed.Plan.ID, err)
	}
	if _, err = service.Create(ctx, f.nodeID, "v0.70.1", artifact, sha, f.userID, "upgrade-replay"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("same key with changed upgrade request got %v", err)
	}
	if _, err = service.Create(ctx, f.nodeID, "v0.70.0", artifact, sha, "different-actor", "upgrade-replay"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("same key with different actor got %v", err)
	}
}

func TestConcurrentIdempotencyCreatesExactlyOneUpgrade(t *testing.T) {
	f := newUpgradeFixture(t)
	cipher, err := configcrypto.LoadOrCreate(filepath.Join(t.TempDir(), "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	taskService := task.New(f.store, nil, events.New())
	service := New(f.store, nil, taskService, events.New(), time.Minute, cipher)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			if _, err := service.Create(context.Background(), f.nodeID, "v0.70.0", "https://download.example/frp", strings.Repeat("c", 64), f.userID, "concurrent-key-"+string(rune('a'+index))); err == nil {
				successes.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful concurrent creates=%d", successes.Load())
	}
	if _, err := taskService.Inspect(context.Background(), f.nodeID, f.userID, "inspect-alongside-change"); err != nil {
		t.Fatalf("inspect incorrectly occupied by node mutation lock: %v", err)
	}
	if _, err := taskService.CollectRuntime(context.Background(), f.nodeID, f.userID, "runtime-alongside-change"); err != nil {
		t.Fatalf("runtime collection incorrectly occupied by node mutation lock: %v", err)
	}
}

func TestConcurrentObserveTransitionCannotRaceDangerousTaskCreation(t *testing.T) {
	f := newUpgradeFixture(t)
	cipher, err := configcrypto.LoadOrCreate(filepath.Join(t.TempDir(), "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	service := New(f.store, nil, task.New(f.store, nil, events.New()), events.New(), time.Minute, cipher)
	for i := range 24 {
		nodeID := addManagedNode(t, f)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, _ = service.Create(context.Background(), nodeID, "v0.70.0", "https://download.example/frp", strings.Repeat("d", 64), f.userID, "mode-race-"+string(rune('a'+i)))
		}()
		go func() {
			defer wg.Done()
			<-start
			_, _ = f.store.SetNodeManagementMode(context.Background(), nodeID, "observe", time.Now().UTC())
		}()
		close(start)
		wg.Wait()
		node, err := f.store.NodeByID(context.Background(), nodeID)
		if err != nil {
			t.Fatal(err)
		}
		active, err := f.store.ListTasks(context.Background(), 10, "", "queued", nodeID)
		if err != nil {
			t.Fatal(err)
		}
		if node.ManagementMode == "observe" && len(active.Items) != 0 {
			t.Fatalf("iteration %d committed observe mode with active dangerous task", i)
		}
	}
}

func TestHistoricalKeyDecryptsAndWrongAADFailsClosed(t *testing.T) {
	f := newUpgradeFixture(t)
	dir := t.TempDir()
	oldPath, newPath := filepath.Join(dir, "old.key"), filepath.Join(dir, "new.key")
	for _, path := range []string{oldPath, newPath} {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, key, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldRing, err := configcrypto.LoadKeyRing(oldPath, "old", map[string]string{"old": oldPath})
	if err != nil {
		t.Fatal(err)
	}
	tasks := task.New(f.store, nil, events.New())
	oldService := New(f.store, nil, tasks, events.New(), time.Minute, oldRing)
	created, err := oldService.Create(context.Background(), f.nodeID, "v0.70.0", "https://download.example/frp?token=old", strings.Repeat("b", 64), f.userID, "old-key")
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := configcrypto.LoadKeyRing(oldPath, "new", map[string]string{"old": oldPath, "new": newPath})
	if err != nil {
		t.Fatal(err)
	}
	rotatedService := New(f.store, nil, tasks, events.New(), time.Minute, rotated)
	if material, err := rotatedService.MaterializeUpgrade(context.Background(), created.Plan.ID); err != nil || !strings.Contains(material.ArtifactURL, "token=old") {
		t.Fatalf("historical key materialization failed: %+v %v", material, err)
	}
	if _, err := f.store.CancelTask(context.Background(), created.Task.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	stored, err := f.store.UpgradePlanByID(context.Background(), created.Plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	wrongID, taskID, now := uuid.NewString(), uuid.NewString(), time.Now().UTC()
	stored.ID, stored.TaskID, stored.CreatedAt, stored.UpdatedAt = wrongID, taskID, now, now
	badTask := domain.Task{ID: taskID, Type: "frp_upgrade", State: "queued", NodeID: f.nodeID, IdempotencyKey: "wrong-aad", RequestedBy: f.userID, Payload: "{}", UpgradePlanID: &wrongID, CreatedAt: now, UpdatedAt: now}
	step := domain.TaskStep{ID: uuid.NewString(), TaskID: taskID, Name: "frp_upgrade", State: "queued", Attempt: 1, CreatedAt: now, UpdatedAt: now}
	if err = f.store.CreateUpgradePlanTask(context.Background(), stored, badTask, step); err != nil {
		t.Fatal(err)
	}
	if _, err = rotatedService.MaterializeUpgrade(context.Background(), wrongID); err == nil {
		t.Fatal("ciphertext accepted with a different plan ID AAD")
	}
}
