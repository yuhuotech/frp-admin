package configmgr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

type fakeVerifier struct {
	err     error
	calls   int
	content []byte
	path    string
}

type blockingVerifier struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockingVerifier) Verify(context.Context, string, string) error {
	close(b.entered)
	<-b.release
	return nil
}

func (f *fakeVerifier) Verify(_ context.Context, binary, candidate string) error {
	f.calls++
	f.path = candidate
	if binary != "/usr/local/bin/frpc" {
		return errors.New("unexpected binary")
	}
	f.content, _ = os.ReadFile(candidate)
	return f.err
}

type fakeLifecycle struct {
	applyErrors  []error
	healthErrors []error
	strategies   []string
}

func (f *fakeLifecycle) ApplyConfigStrategy(_ context.Context, strategy string) error {
	f.strategies = append(f.strategies, strategy)
	if len(f.applyErrors) == 0 {
		return nil
	}
	err := f.applyErrors[0]
	f.applyErrors = f.applyErrors[1:]
	return err
}

func (f *fakeLifecycle) Healthy(context.Context) error {
	if len(f.healthErrors) == 0 {
		return nil
	}
	err := f.healthErrors[0]
	f.healthErrors = f.healthErrors[1:]
	return err
}

func (f *fakeLifecycle) Controllable(context.Context) error { return nil }

func fixture(t *testing.T, lifecycle *fakeLifecycle, verifier *fakeVerifier) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "etc", "frpc.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("old = true\n"), 0640); err != nil {
		t.Fatal(err)
	}
	m, err := New(Options{Role: "client", BinaryPath: "/usr/local/bin/frpc", ConfigPath: configPath,
		StateDir: filepath.Join(dir, "state"), Verifier: verifier, Lifecycle: lifecycle,
		HealthTimeout: time.Nanosecond, HealthPoll: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	return m, configPath
}

func checksum(v []byte) string { h := sha256.Sum256(v); return hex.EncodeToString(h[:]) }

func assertCode(t *testing.T, err error, code agentv1.ErrorCode) {
	t.Helper()
	var target *Error
	if !errors.As(err, &target) || target.Code != code {
		t.Fatalf("error=%v, want code %s", err, code)
	}
}

func TestApplyConfigTransaction(t *testing.T) {
	lifecycle, verifier := &fakeLifecycle{}, &fakeVerifier{}
	m, configPath := fixture(t, lifecycle, verifier)
	candidate := []byte("new = true\n")
	if err := m.Apply(context.Background(), "revision-1", checksum(candidate), candidate, "reload"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(configPath)
	if string(got) != string(candidate) || string(verifier.content) != string(candidate) {
		t.Fatalf("config=%q verified=%q", got, verifier.content)
	}
	if filepath.Ext(verifier.path) != ".toml" {
		t.Fatalf("candidate must preserve config extension: %s", verifier.path)
	}
	if len(lifecycle.strategies) != 1 || lifecycle.strategies[0] != "reload" {
		t.Fatalf("strategies=%v", lifecycle.strategies)
	}
	meta, err := m.loadMetadata()
	if err != nil {
		t.Fatal(err)
	}
	if meta.CurrentRevision != "revision-1" || len(meta.History) != 1 {
		t.Fatalf("metadata=%+v", meta)
	}
	backup, _ := os.ReadFile(meta.History[0].Path)
	if string(backup) != "old = true\n" {
		t.Fatalf("backup=%q", backup)
	}
}

func TestChecksumAndVerifyFailuresDoNotReplaceCurrent(t *testing.T) {
	for _, tc := range []struct {
		name      string
		sha       string
		verifyErr error
		code      agentv1.ErrorCode
	}{
		{"checksum", "bad", nil, agentv1.ErrorCode_ERROR_CODE_CHECKSUM_MISMATCH},
		{"verify", checksum([]byte("invalid")), errors.New("invalid config"), agentv1.ErrorCode_ERROR_CODE_VERIFY_FAILED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lifecycle, verifier := &fakeLifecycle{}, &fakeVerifier{err: tc.verifyErr}
			m, configPath := fixture(t, lifecycle, verifier)
			err := m.Apply(context.Background(), "revision-1", tc.sha, []byte("invalid"), "restart")
			assertCode(t, err, tc.code)
			got, _ := os.ReadFile(configPath)
			if string(got) != "old = true\n" {
				t.Fatalf("config changed: %q", got)
			}
			if len(lifecycle.strategies) != 0 {
				t.Fatalf("service changed: %v", lifecycle.strategies)
			}
		})
	}
}

func TestServiceAndHealthFailuresRestorePreviousConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		apply  []error
		health []error
		code   agentv1.ErrorCode
	}{
		{"service", []error{errors.New("restart failed"), nil}, nil, agentv1.ErrorCode_ERROR_CODE_SERVICE_OPERATION_FAILED},
		{"health", nil, []error{errors.New("not active"), nil}, agentv1.ErrorCode_ERROR_CODE_HEALTHCHECK_FAILED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lifecycle := &fakeLifecycle{applyErrors: tc.apply, healthErrors: tc.health}
			m, configPath := fixture(t, lifecycle, &fakeVerifier{})
			content := []byte("new = true\n")
			err := m.Apply(context.Background(), "revision-1", checksum(content), content, "restart")
			assertCode(t, err, tc.code)
			got, _ := os.ReadFile(configPath)
			if string(got) != "old = true\n" {
				t.Fatalf("old config not restored: %q", got)
			}
			if len(lifecycle.strategies) != 2 {
				t.Fatalf("restore did not reapply service strategy: %v", lifecycle.strategies)
			}
		})
	}
}

func TestRollbackToRecentRevision(t *testing.T) {
	m, configPath := fixture(t, &fakeLifecycle{}, &fakeVerifier{})
	r1, r2 := []byte("value = 1\n"), []byte("value = 2\n")
	if err := m.Apply(context.Background(), "r1", checksum(r1), r1, "restart"); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(context.Background(), "r2", checksum(r2), r2, "restart"); err != nil {
		t.Fatal(err)
	}
	if err := m.Rollback(context.Background(), "r1", "restart"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(configPath)
	if string(got) != string(r1) {
		t.Fatalf("rollback config=%q", got)
	}
}

func TestServerRoleRejectsReloadBeforeMutation(t *testing.T) {
	lifecycle, verifier := &fakeLifecycle{}, &fakeVerifier{}
	m, configPath := fixture(t, lifecycle, verifier)
	m.role = "server"
	content := []byte("new = true\n")
	err := m.Apply(context.Background(), "r1", checksum(content), content, "reload")
	assertCode(t, err, agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED)
	got, _ := os.ReadFile(configPath)
	if string(got) != "old = true\n" || verifier.calls != 0 || len(lifecycle.strategies) != 0 {
		t.Fatalf("reload rejection mutated state: config=%q verify=%d strategies=%v", got, verifier.calls, lifecycle.strategies)
	}
}

func TestRecoverInterruptedReplacement(t *testing.T) {
	lifecycle, verifier := &fakeLifecycle{}, &fakeVerifier{}
	m, configPath := fixture(t, lifecycle, verifier)
	backupDir := filepath.Join(m.stateDir, "backups", "config")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(backupDir, "crash.toml")
	if err := os.WriteFile(backup, []byte("old = true\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := m.saveTransaction(transactionState{Backup: backupEntry{Path: backup}, Strategy: "restart", Mode: uint32(0640)}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("partial = true\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := m.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(configPath)
	if string(got) != "old = true\n" {
		t.Fatalf("config=%q", got)
	}
	if _, err := os.Stat(m.transactionPath()); !os.IsNotExist(err) {
		t.Fatalf("transaction remains: %v", err)
	}
}

func TestFinalizeFailureKeepsDurableRecoveryMaterial(t *testing.T) {
	lifecycle, verifier := &fakeLifecycle{}, &fakeVerifier{}
	m, configPath := fixture(t, lifecycle, verifier)
	m.finalizeTransaction = func(string) error { return errors.New("injected marker removal failure") }
	candidate := []byte("new = true\n")
	err := m.Apply(context.Background(), "revision-1", checksum(candidate), candidate, "restart")
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED ||
		!typed.BackupCreated || !typed.Changed || !typed.RollbackAttempted || typed.RollbackSucceeded {
		t.Fatalf("error=%+v", typed)
	}
	got, _ := os.ReadFile(configPath)
	if string(got) != "old = true\n" {
		t.Fatalf("old config was not restored: %q", got)
	}
	data, readErr := os.ReadFile(m.transactionPath())
	if readErr != nil {
		t.Fatalf("recovery marker was lost: %v", readErr)
	}
	var tx transactionState
	if err := json.Unmarshal(data, &tx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tx.Backup.Path); err != nil {
		t.Fatalf("backup was deleted before marker finalization: %v", err)
	}
	m.finalizeTransaction = removeSynced
	if err := m.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.transactionPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker remains after recovery: %v", err)
	}
	if _, err := os.Stat(tx.Backup.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery backup remains after durable marker deletion: %v", err)
	}
}

func TestApplyCASRejectsTargetMutationDuringVerification(t *testing.T) {
	for _, tc := range []struct {
		name   string
		code   agentv1.ErrorCode
		mutate func(*testing.T, string)
	}{
		{name: "inode replacement", code: agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, mutate: func(t *testing.T, path string) {
			replacement := filepath.Join(filepath.Dir(path), "external.toml")
			if err := os.WriteFile(replacement, []byte("external = true\n"), 0640); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacement, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "same inode rewrite", code: agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, mutate: func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("external = true\n"), 0640); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lifecycle := &fakeLifecycle{}
			verifier := &blockingVerifier{entered: make(chan struct{}), release: make(chan struct{})}
			dir := t.TempDir()
			configPath := filepath.Join(dir, "etc", "frpc.toml")
			if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
				t.Fatal(err)
			}
			original := []byte("old = true\n")
			if err := os.WriteFile(configPath, original, 0640); err != nil {
				t.Fatal(err)
			}
			m, err := New(Options{Role: "client", BinaryPath: "/usr/local/bin/frpc", ConfigPath: configPath,
				StateDir: filepath.Join(dir, "state"), Verifier: verifier, Lifecycle: lifecycle})
			if err != nil {
				t.Fatal(err)
			}
			candidate := []byte("new = true\n")
			done := make(chan error, 1)
			go func() {
				done <- m.ApplyCAS(context.Background(), "revision-cas", checksum(candidate), candidate, "restart", checksum(original))
			}()
			<-verifier.entered
			tc.mutate(t, configPath)
			close(verifier.release)
			err = <-done
			assertCode(t, err, tc.code)
			got, _ := os.ReadFile(configPath)
			if string(got) != "external = true\n" {
				t.Fatalf("external change was overwritten: %q", got)
			}
			if len(lifecycle.strategies) != 0 {
				t.Fatalf("service was restarted after CAS failure: %v", lifecycle.strategies)
			}
		})
	}
}

func TestApplyCASAtomicExchangeRestoresLastMomentExternalWrite(t *testing.T) {
	lifecycle, verifier := &fakeLifecycle{}, &fakeVerifier{}
	m, configPath := fixture(t, lifecycle, verifier)
	m.useAtomicExchange = true
	m.exchange = testExchange
	m.beforeExchange = func() {
		if err := os.WriteFile(configPath, []byte("external = true\n"), 0640); err != nil {
			t.Errorf("inject external write: %v", err)
		}
	}
	original := []byte("old = true\n")
	candidate := []byte("new = true\n")
	err := m.ApplyCAS(context.Background(), "revision-race", checksum(candidate), candidate, "restart", checksum(original))
	assertCode(t, err, agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED)
	got, _ := os.ReadFile(configPath)
	if string(got) != "external = true\n" {
		t.Fatalf("last-moment external write was not atomically restored: %q", got)
	}
	if len(lifecycle.strategies) != 0 {
		t.Fatalf("service restarted after exchange race: %v", lifecycle.strategies)
	}
}

func TestRootManagerPreservesAllowlistedConfigOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	lifecycle, verifier := &fakeLifecycle{}, &fakeVerifier{}
	m, configPath := fixture(t, lifecycle, verifier)
	owner := uint32(12345)
	if err := os.Chown(configPath, int(owner), int(owner)); err != nil {
		t.Fatal(err)
	}
	m.configOwnerUID = &owner
	candidate := []byte("new = true\n")
	if err := m.Apply(context.Background(), "owner-r1", checksum(candidate), candidate, "restart"); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(configPath)
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != owner || stat.Gid != owner || info.Mode().Perm() != 0640 {
		t.Fatalf("owner/mode not preserved: uid=%d gid=%d mode=%04o", stat.Uid, stat.Gid, info.Mode().Perm())
	}
}

func testExchange(left, right string) (bool, error) {
	temporary := right + ".test-exchange"
	if err := os.Rename(left, temporary); err != nil {
		return false, err
	}
	if err := os.Rename(right, left); err != nil {
		_ = os.Rename(temporary, left)
		return false, err
	}
	if err := os.Rename(temporary, right); err != nil {
		return true, err
	}
	return true, nil
}
