package configcrypto

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedAtRestAndTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	c, e := LoadOrCreate(path)
	if e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	plain := []byte("serverAddr = \"secret.example\"")
	encrypted, nonce, _, e := c.Seal("node", 1, plain)
	if e != nil {
		t.Fatal(e)
	}
	if string(encrypted) == string(plain) {
		t.Fatal("plaintext stored")
	}
	opened, e := c.Open("node", 1, encrypted, nonce)
	if e != nil || string(opened) != string(plain) {
		t.Fatalf("open=%q err=%v", opened, e)
	}
	encrypted[0] ^= 1
	if _, e = c.Open("node", 1, encrypted, nonce); e == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, e = c.Open("other", 1, encrypted, nonce); e == nil {
		t.Fatal("wrong AAD accepted")
	}
}
func TestSecretKeyRingReadsOldAndWritesCurrent(t *testing.T) {
	dir := t.TempDir()
	oldPath, newPath := filepath.Join(dir, "old.key"), filepath.Join(dir, "new.key")
	for _, path := range []string{oldPath, newPath} {
		key := make([]byte, 32)
		if _, e := rand.Read(key); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, key, 0o600); e != nil {
			t.Fatal(e)
		}
	}
	oldRing, e := LoadKeyRing(oldPath, "old", map[string]string{"old": oldPath})
	if e != nil {
		t.Fatal(e)
	}
	encrypted, nonce, version, e := oldRing.SealSecret("TOKEN", []byte("value"))
	if e != nil || version != "old" {
		t.Fatalf("version=%s err=%v", version, e)
	}
	ring, e := LoadKeyRing(oldPath, "new", map[string]string{"old": oldPath, "new": newPath})
	if e != nil {
		t.Fatal(e)
	}
	plain, e := ring.OpenSecret("TOKEN", "old", encrypted, nonce)
	if e != nil || string(plain) != "value" {
		t.Fatalf("old decrypt=%q err=%v", plain, e)
	}
	_, _, version, e = ring.SealSecret("TOKEN", []byte("new"))
	if e != nil || version != "new" {
		t.Fatalf("new version=%s err=%v", version, e)
	}
}

func TestSecretRejectsTamperedCiphertextAndWrongAAD(t *testing.T) {
	c, err := LoadOrCreate(filepath.Join(t.TempDir(), "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, nonce, version, err := c.SealSecret("FRP_TOKEN", []byte("sensitive-value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.OpenSecret("OTHER_TOKEN", version, encrypted, nonce); err == nil {
		t.Fatal("secret ciphertext accepted with a different name in AAD")
	}
	encrypted[0] ^= 1
	if _, err = c.OpenSecret("FRP_TOKEN", version, encrypted, nonce); err == nil {
		t.Fatal("tampered secret ciphertext accepted")
	}
}
