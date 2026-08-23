package configcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

type Cipher struct {
	aead           cipher.AEAD
	secretKeys     map[string]cipher.AEAD
	currentVersion string
}

func LoadOrCreate(path string) (*Cipher, error) {
	data, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		if e = os.MkdirAll(filepath.Dir(path), 0o700); e != nil {
			return nil, e
		}
		data = make([]byte, 32)
		if _, e = io.ReadFull(rand.Reader, data); e != nil {
			return nil, e
		}
		tmp := path + ".tmp"
		if e = os.WriteFile(tmp, data, 0o600); e != nil {
			return nil, e
		}
		if e = os.Chmod(tmp, 0o600); e != nil {
			return nil, e
		}
		if e = os.Rename(tmp, path); e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("master key must contain exactly 32 bytes, got %d", len(data))
	}
	block, e := aes.NewCipher(data)
	if e != nil {
		return nil, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	return &Cipher{aead: aead, secretKeys: map[string]cipher.AEAD{"1": aead}, currentVersion: "1"}, nil
}
func LoadKeyRing(path, current string, keyFiles map[string]string) (*Cipher, error) {
	c, e := LoadOrCreate(path)
	if e != nil {
		return nil, e
	}
	if len(keyFiles) == 0 {
		return c, nil
	}
	c.secretKeys = map[string]cipher.AEAD{}
	for version, keyPath := range keyFiles {
		data, e := os.ReadFile(keyPath)
		if e != nil {
			return nil, e
		}
		if len(data) != 32 {
			return nil, fmt.Errorf("master key version %s must contain 32 bytes", version)
		}
		block, e := aes.NewCipher(data)
		if e != nil {
			return nil, e
		}
		aead, e := cipher.NewGCM(block)
		if e != nil {
			return nil, e
		}
		c.secretKeys[version] = aead
	}
	if current == "" {
		return nil, errors.New("master key currentVersion is required")
	}
	if c.secretKeys[current] == nil {
		return nil, fmt.Errorf("current master key version %s is not configured", current)
	}
	c.currentVersion = current
	return c, nil
}
func (c *Cipher) Seal(nodeID string, version int64, plaintext []byte) (encrypted, nonce []byte, sha string, err error) {
	nonce = make([]byte, c.aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, "", err
	}
	encrypted = c.aead.Seal(nil, nonce, plaintext, aad(nodeID, version))
	sum := sha256.Sum256(plaintext)
	return encrypted, nonce, hex.EncodeToString(sum[:]), nil
}
func (c *Cipher) Open(nodeID string, version int64, encrypted, nonce []byte) ([]byte, error) {
	return c.aead.Open(nil, nonce, encrypted, aad(nodeID, version))
}
func (c *Cipher) SealSecret(name string, value []byte) (encrypted, nonce []byte, keyVersion string, err error) {
	keyVersion = c.currentVersion
	aead := c.secretKeys[keyVersion]
	nonce = make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, "", err
	}
	return aead.Seal(nil, nonce, value, []byte("frp-admin/secret/v1\x00"+name+"\x00"+keyVersion)), nonce, keyVersion, nil
}
func (c *Cipher) OpenSecret(name, keyVersion string, encrypted, nonce []byte) ([]byte, error) {
	aead := c.secretKeys[keyVersion]
	if aead == nil {
		return nil, errors.New("secret key version is unavailable")
	}
	return aead.Open(nil, nonce, encrypted, []byte("frp-admin/secret/v1\x00"+name+"\x00"+keyVersion))
}
func (c *Cipher) HasKeyVersion(version string) bool {
	return c != nil && c.secretKeys[version] != nil
}
func aad(nodeID string, version int64) []byte {
	return []byte("frp-admin/config/v1\x00" + nodeID + "\x00" + strconv.FormatInt(version, 10))
}
