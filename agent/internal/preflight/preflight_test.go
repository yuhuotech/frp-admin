package preflight

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagedFileRejectsSymlinkAndWritableMode(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ManagedFile(link); err == nil {
		t.Fatal("expected symlink rejection")
	}
	if err := os.Chmod(target, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := ManagedFile(target); err == nil {
		t.Fatal("expected writable mode rejection")
	}
}

func TestSecureStatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := SecureStateDir(path); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0700 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func TestSecureStateRejectsUserControlledSymlinkAncestor(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := SecureStateDir(filepath.Join(link, "state")); err == nil {
		t.Fatal("expected symlink ancestor rejection")
	}
}

func TestManagedFileRejectsWritableParent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := ManagedFile(target); err == nil {
		t.Fatal("expected writable parent rejection")
	}
}
