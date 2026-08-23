package certmgr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

func issue(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, public any, serial int64, node, role string, notAfter time.Time) []byte {
	t.Helper()
	identity, _ := url.Parse("spiffe://frp-admin/" + role + "/" + node)
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: node}, DNSNames: []string{node}, URIs: []*url.URL{identity}, NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func fixture(t *testing.T) (*Manager, *x509.Certificate, *ecdsa.PrivateKey, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	if err := os.MkdirAll(pki, 0700); err != nil {
		t.Fatal(err)
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certPath, keyPath, caPath := filepath.Join(pki, "client.pem"), filepath.Join(pki, "client-key.pem"), filepath.Join(pki, "ca.pem")
	if err := os.WriteFile(certPath, issue(t, ca, caKey, &key.PublicKey, 2, "node-1", "client", time.Now().Add(time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := New(Options{NodeID: "node-1", Role: "client", CertFile: certPath, KeyFile: keyPath, CAFile: caPath, StateDir: dir, RotateBefore: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return m, ca, caKey, certPath, keyPath, caPath
}

func TestCertificateRotationAndPermissions(t *testing.T) {
	m, ca, caKey, certPath, keyPath, caPath := fixture(t)
	request, err := m.RotationRequest(time.Now())
	if err != nil || request == nil {
		t.Fatalf("request=%v err=%v", request, err)
	}
	block, _ := pem.Decode(request.GetCsrPem())
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cert := issue(t, ca, caKey, csr.PublicKey, 3, "node-1", "client", time.Now().Add(30*24*time.Hour))
	caPEM, _ := os.ReadFile(caPath)
	leaf, _, _ := parseCertificates(cert)
	if err := m.Apply(&agentv1.RotateCertificate{RequestId: request.GetRequestId(), CertificatePem: cert, CaCertificatePem: caPEM, CertificateExpiresAtUnixMs: leaf.NotAfter.UnixMilli()}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{certPath, keyPath} {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode=%o", path, info.Mode().Perm())
		}
	}
	info, _ := os.Stat(filepath.Join(m.options.StateDir, "pki"))
	if info.Mode().Perm() != 0700 {
		t.Fatalf("pki mode=%o", info.Mode().Perm())
	}
}

func TestInvalidRoleCertificateKeepsOldPair(t *testing.T) {
	m, ca, caKey, certPath, _, _ := fixture(t)
	old, _ := os.ReadFile(certPath)
	request, _ := m.RotationRequest(time.Now())
	block, _ := pem.Decode(request.GetCsrPem())
	csr, _ := x509.ParseCertificateRequest(block.Bytes)
	bad := issue(t, ca, caKey, csr.PublicKey, 3, "node-1", "server", time.Now().Add(30*24*time.Hour))
	if err := m.Apply(&agentv1.RotateCertificate{RequestId: request.GetRequestId(), CertificatePem: bad}, time.Now()); err == nil {
		t.Fatal("expected role SAN rejection")
	}
	got, _ := os.ReadFile(certPath)
	if string(got) != string(old) {
		t.Fatal("current certificate changed after rejection")
	}
}

func TestRecoverInterruptedKeypairCommit(t *testing.T) {
	m, _, _, certPath, keyPath, _ := fixture(t)
	oldCert, _ := os.ReadFile(certPath)
	oldKey, _ := os.ReadFile(keyPath)
	certBackup := filepath.Join(m.pkiDir(), "rotation-cert.backup")
	keyBackup := filepath.Join(m.pkiDir(), "rotation-key.backup")
	if err := copyAtomic(certPath, certBackup); err != nil {
		t.Fatal(err)
	}
	if err := copyAtomic(keyPath, keyBackup); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(m.transactionPath(), transaction{CertBackup: certBackup, KeyBackup: keyBackup}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("partial-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Recover(); err != nil {
		t.Fatal(err)
	}
	gotCert, _ := os.ReadFile(certPath)
	gotKey, _ := os.ReadFile(keyPath)
	if string(gotCert) != string(oldCert) || string(gotKey) != string(oldKey) {
		t.Fatal("old keypair was not restored")
	}
}
