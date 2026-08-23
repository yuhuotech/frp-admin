package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/config"
)

func TestLoadOrCreatePersistsPKIAndSignsNodeIdentity(t *testing.T) {
	dir := t.TempDir()
	cfg := config.PKIConfig{Directory: dir, ServerNames: []string{"control.internal", "127.0.0.1"}}
	m, e := LoadOrCreate(cfg)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"ca.crt", "ca.key", "server.crt", "server.key"} {
		info, e := os.Stat(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o", name, info.Mode().Perm())
		}
	}
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		t.Fatal(e)
	}
	certPEM, _, e := m.SignClient(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), "node-123", 30)
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(certPEM)
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://frp-admin/node/node-123" {
		t.Fatalf("unexpected URI SAN: %v", cert.URIs)
	}
	if cert.DNSNames[0] != "node-123" {
		t.Fatalf("unexpected DNS SAN: %v", cert.DNSNames)
	}
	firstCA := string(m.CAPEM())
	m2, e := LoadOrCreate(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if string(m2.CAPEM()) != firstCA {
		t.Fatal("CA changed across reload")
	}
}

func TestLoadOrCreateRejectsPartialPKI(t *testing.T) {
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("partial"), 0o600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadOrCreate(config.PKIConfig{Directory: dir}); e == nil {
		t.Fatal("partial PKI was accepted")
	}
}

func TestSignClientCSRUsesServerIdentity(t *testing.T) {
	manager, err := LoadOrCreate(config.PKIConfig{Directory: t.TempDir(), ServerNames: []string{"localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"attacker.example"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	certPEM, expires, err := manager.SignClientCSR(csrPEM, "node-1", "client", 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "node-1" {
		t.Fatalf("server did not replace CSR DNS names: %v", cert.DNSNames)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://frp-admin/client/node-1" {
		t.Fatalf("unexpected identity URIs: %v", cert.URIs)
	}
	if err := cert.CheckSignatureFrom(manager.ca); err != nil {
		t.Fatalf("certificate is not signed by Agent CA: %v", err)
	}
	if !expires.Equal(cert.NotAfter) || expires.UnixMilli() != cert.NotAfter.UnixMilli() {
		t.Fatalf("CSR expiry metadata %s differs from certificate NotAfter %s", expires, cert.NotAfter)
	}
}

func TestSignClientReturnsEncodedCertificateExpiry(t *testing.T) {
	manager, err := LoadOrCreate(config.PKIConfig{Directory: t.TempDir(), ServerNames: []string{"localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, expires, err := manager.SignClient(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), "node-expiry", 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certificatePEM)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !expires.Equal(certificate.NotAfter) || expires.UnixMilli() != certificate.NotAfter.UnixMilli() {
		t.Fatalf("enrollment expiry metadata %s differs from certificate NotAfter %s", expires, certificate.NotAfter)
	}
}
