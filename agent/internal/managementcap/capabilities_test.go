package managementcap

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
)

func TestDetectForUIDRequiresSameNonRootServiceIdentity(t *testing.T) {
	uid := uint32(os.Geteuid())
	if uid == 0 {
		t.Skip("test requires a non-root runner")
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "frpc.toml")
	binaryPath := filepath.Join(dir, "frpc")
	if err := os.WriteFile(configPath, []byte("x=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binaryPath, []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	got := detectForUID(uid, uid, configPath, binaryPath)
	for _, capability := range []string{"config.apply", "config.rollback", "frp.upgrade"} {
		if !slices.Contains(got, capability) {
			t.Fatalf("capabilities=%v missing %s", got, capability)
		}
	}
	if got := detectForUID(uid, uid+1, configPath, binaryPath); len(got) != 0 {
		t.Fatalf("different service identity capabilities=%v", got)
	}
}

func TestSafelyMutableRejectsWritableParentAndForeignOwner(t *testing.T) {
	uid := uint32(os.Geteuid())
	dir := t.TempDir()
	path := filepath.Join(dir, "frpc.toml")
	if err := os.WriteFile(path, []byte("x=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if safelyMutableBy(path, uid, false) {
		t.Fatal("writable parent was accepted")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := info.Sys().(*syscall.Stat_t); !ok {
		t.Fatal("stat identity unavailable")
	}
}

func TestUpgradeCapabilityRequiresBothConfigAndBinaryPreflight(t *testing.T) {
	uid := uint32(os.Geteuid())
	if uid == 0 {
		t.Skip("test requires a non-root runner")
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "frpc.toml")
	binaryPath := filepath.Join(dir, "frpc")
	if err := os.WriteFile(configPath, []byte("x=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binaryPath, []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configPath, 0000); err != nil {
		t.Fatal(err)
	}
	got := detectForUID(uid, uid, configPath, binaryPath)
	if slices.Contains(got, "frp.upgrade") {
		t.Fatalf("upgrade advertised without readable config preflight: %v", got)
	}
	if err := os.Chmod(configPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(binaryPath, 0600); err != nil {
		t.Fatal(err)
	}
	got = detectForUID(uid, uid, configPath, binaryPath)
	if slices.Contains(got, "frp.upgrade") {
		t.Fatalf("upgrade advertised without executable binary preflight: %v", got)
	}
}
