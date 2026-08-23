package upgrader

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

type fileDownloader struct{ source, checksum string }

type errorDownloader struct{ err error }

func (d errorDownloader) Download(context.Context, string, string, int64, []string) (string, error) {
	return "", d.err
}

func (d fileDownloader) Download(_ context.Context, _ string, destination string, _ int64, _ []string) (string, error) {
	in, err := os.Open(d.source)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.Create(destination)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(out, in)
	closeErr := out.Close()
	if err != nil {
		return "", err
	}
	return d.checksum, closeErr
}

type fakeRunner struct{ verifyErr error }

func (fakeRunner) Version(context.Context, string) (string, error) { return "0.70.1", nil }
func (r fakeRunner) Verify(context.Context, string, string) error  { return r.verifyErr }

type fakeUpgradeLifecycle struct {
	stops, starts int
	startErrors   []error
}

func (f *fakeUpgradeLifecycle) Stop(context.Context) error { f.stops++; return nil }
func (f *fakeUpgradeLifecycle) Start(context.Context) error {
	f.starts++
	if len(f.startErrors) == 0 {
		return nil
	}
	err := f.startErrors[0]
	f.startErrors = f.startErrors[1:]
	return err
}
func (f *fakeUpgradeLifecycle) Healthy(context.Context) error      { return nil }
func (f *fakeUpgradeLifecycle) Controllable(context.Context) error { return nil }

func upgradeFixture(t *testing.T, runner BinaryRunner, lifecycle *fakeUpgradeLifecycle, reportedChecksum string) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "bin", "frpc")
	config := filepath.Join(dir, "etc", "frpc.toml")
	if err := os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(config), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("old-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("serverAddr='x'"), 0600); err != nil {
		t.Fatal(err)
	}
	archive := makeTarGz(t, map[string][]byte{"frp/frpc": []byte("new-binary")})
	m, err := New(Options{Role: "client", BinaryPath: binary, ConfigPath: config, StateDir: filepath.Join(dir, "state"),
		AllowedHosts: []string{"github.com"}, MaxArtifactBytes: 1024, Downloader: fileDownloader{source: archive, checksum: reportedChecksum},
		Runner: runner, Lifecycle: lifecycle, HealthTimeout: time.Millisecond, HealthPoll: time.Nanosecond, StableWindow: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	return m, binary
}

func errorCode(t *testing.T, err error, want agentv1.ErrorCode) {
	t.Helper()
	var target *Error
	if !errors.As(err, &target) || target.Code != want {
		t.Fatalf("error=%v want=%s", err, want)
	}
}

func TestUpgradeChecksumMismatch(t *testing.T) {
	lifecycle := &fakeUpgradeLifecycle{}
	m, binary := upgradeFixture(t, fakeRunner{}, lifecycle, "wrong")
	err := m.Upgrade(context.Background(), "v0.70.1", "https://github.com/frp.tar.gz", "expected")
	errorCode(t, err, agentv1.ErrorCode_ERROR_CODE_CHECKSUM_MISMATCH)
	got, _ := os.ReadFile(binary)
	if string(got) != "old-binary" || lifecycle.stops != 0 {
		t.Fatalf("binary=%q stops=%d", got, lifecycle.stops)
	}
}

func TestUpgradeDiagnosticDoesNotContainPresignedURL(t *testing.T) {
	lifecycle := &fakeUpgradeLifecycle{}
	m, _ := upgradeFixture(t, fakeRunner{}, lifecycle, "sum")
	secret := "presigned-top-secret"
	m.options.Downloader = errorDownloader{err: errors.New("artifact download request failed")}
	err := m.Upgrade(context.Background(), "v0.70.1", "https://github.com/frp.tar.gz?X-Signature="+secret, "sum")
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "X-Signature") {
		t.Fatalf("unsafe diagnostic=%v", err)
	}
}

func TestUpgradeVerifyFailureDoesNotStopService(t *testing.T) {
	lifecycle := &fakeUpgradeLifecycle{}
	m, binary := upgradeFixture(t, fakeRunner{verifyErr: errors.New("invalid")}, lifecycle, "sum")
	err := m.Upgrade(context.Background(), "v0.70.1", "https://github.com/frp.tar.gz", "sum")
	errorCode(t, err, agentv1.ErrorCode_ERROR_CODE_VERIFY_FAILED)
	got, _ := os.ReadFile(binary)
	if string(got) != "old-binary" || lifecycle.stops != 0 {
		t.Fatalf("binary=%q stops=%d", got, lifecycle.stops)
	}
}

func TestStartFailureRestoresOldBinary(t *testing.T) {
	lifecycle := &fakeUpgradeLifecycle{startErrors: []error{errors.New("start failed"), nil}}
	m, binary := upgradeFixture(t, fakeRunner{}, lifecycle, "sum")
	err := m.Upgrade(context.Background(), "v0.70.1", "https://github.com/frp.tar.gz", "sum")
	errorCode(t, err, agentv1.ErrorCode_ERROR_CODE_SERVICE_OPERATION_FAILED)
	got, _ := os.ReadFile(binary)
	if string(got) != "old-binary" {
		t.Fatalf("binary not restored: %q", got)
	}
	if lifecycle.stops != 2 || lifecycle.starts != 2 {
		t.Fatalf("stops=%d starts=%d", lifecycle.stops, lifecycle.starts)
	}
}

func TestRecoverInterruptedBinaryReplacement(t *testing.T) {
	lifecycle := &fakeUpgradeLifecycle{}
	m, binary := upgradeFixture(t, fakeRunner{}, lifecycle, "sum")
	backupDir := filepath.Join(m.options.StateDir, "backups", "bin")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(backupDir, "previous")
	if err := os.WriteFile(backup, []byte("old-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := m.saveTransaction(transactionState{Backup: backup, Mode: uint32(0755)}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("partial-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := m.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(binary)
	if string(got) != "old-binary" {
		t.Fatalf("binary=%q", got)
	}
	if lifecycle.stops != 1 || lifecycle.starts != 1 {
		t.Fatalf("stops=%d starts=%d", lifecycle.stops, lifecycle.starts)
	}
}
