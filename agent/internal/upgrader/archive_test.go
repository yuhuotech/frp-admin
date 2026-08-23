package upgrader

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func checksumBytes(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

func makeTarGz(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "artifact.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, data := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func makeZip(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "artifact.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractRoleBinaryFromTarAndZip(t *testing.T) {
	for _, archive := range []string{makeTarGz(t, map[string][]byte{"frp/frpc": []byte("client"), "frp/frps": []byte("server")}), makeZip(t, map[string][]byte{"frp/frpc": []byte("client")})} {
		destination := filepath.Join(t.TempDir(), "frpc")
		if err := ExtractBinary(archive, "frpc", destination, 100); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(destination)
		if string(got) != "client" {
			t.Fatalf("binary=%q", got)
		}
	}
}

func TestRejectArchivePathTraversal(t *testing.T) {
	for _, archive := range []string{makeTarGz(t, map[string][]byte{"../frpc": []byte("bad")}), makeZip(t, map[string][]byte{"../../frpc": []byte("bad")})} {
		if err := ExtractBinary(archive, "frpc", filepath.Join(t.TempDir(), "frpc"), 100); err == nil {
			t.Fatalf("expected traversal rejection for %s", archive)
		}
	}
}
