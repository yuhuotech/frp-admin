package certmgr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

type Options struct {
	NodeID, Role, CertFile, KeyFile, CAFile, StateDir string
	RotateBefore                                      time.Duration
}
type Manager struct {
	options Options
	mu      sync.RWMutex
}
type pendingState struct {
	RequestID, CurrentSerial, KeyPath string
	ExpiresAt                         int64
}
type transaction struct{ CertBackup, KeyBackup string }

func New(o Options) (*Manager, error) {
	if o.NodeID == "" || o.Role != "client" && o.Role != "server" {
		return nil, errors.New("certificate identity is required")
	}
	for _, path := range []string{o.CertFile, o.KeyFile, o.CAFile, o.StateDir} {
		if !filepath.IsAbs(path) {
			return nil, errors.New("certificate paths must be absolute")
		}
	}
	if o.RotateBefore <= 0 {
		o.RotateBefore = 7 * 24 * time.Hour
	}
	return &Manager{options: o}, nil
}

func (m *Manager) RotationRequest(now time.Time) (*agentv1.CertificateRotationRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cert, err := loadLeaf(m.options.CertFile)
	if err != nil {
		return nil, err
	}
	if now.Add(m.options.RotateBefore).Before(cert.NotAfter) {
		return nil, nil
	}
	if state, err := m.loadPending(); err == nil && state.RequestID != "" {
		csr, readErr := os.ReadFile(filepath.Join(m.pkiDir(), "rotation.csr"))
		if readErr == nil {
			return &agentv1.CertificateRotationRequest{RequestId: state.RequestID, CurrentSerial: state.CurrentSerial, CsrPem: csr, CertificateExpiresAtUnixMs: state.ExpiresAt}, nil
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("load pending certificate rotation: %w", err)
	}
	if err := secureDir(m.pkiDir()); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	identity, _ := url.Parse(fmt.Sprintf("spiffe://frp-admin/%s/%s", m.options.Role, m.options.NodeID))
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{m.options.NodeID}, URIs: []*url.URL{identity}}, key)
	if err != nil {
		return nil, err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	requestID := hex.EncodeToString(random)
	keyPath := filepath.Join(m.pkiDir(), "rotation-key.pem")
	csrPath := filepath.Join(m.pkiDir(), "rotation.csr")
	if err := writeAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if err := writeAtomic(csrPath, csrPEM, 0600); err != nil {
		return nil, err
	}
	state := pendingState{RequestID: requestID, CurrentSerial: cert.SerialNumber.String(), KeyPath: keyPath, ExpiresAt: cert.NotAfter.UnixMilli()}
	if err := writeJSON(m.pendingPath(), state); err != nil {
		return nil, err
	}
	return &agentv1.CertificateRotationRequest{RequestId: requestID, CurrentSerial: state.CurrentSerial, CsrPem: csrPEM, CertificateExpiresAtUnixMs: state.ExpiresAt}, nil
}

func (m *Manager) Apply(response *agentv1.RotateCertificate, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.loadPending()
	if err != nil {
		return fmt.Errorf("load pending rotation: %w", err)
	}
	if state.RequestID == "" || response.GetRequestId() != state.RequestID {
		return errors.New("certificate rotation request id mismatch")
	}
	keyPEM, err := os.ReadFile(state.KeyPath)
	if err != nil {
		return err
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return err
	}
	leaf, chain, err := parseCertificates(response.GetCertificatePem())
	if err != nil {
		return err
	}
	if leaf.SerialNumber.String() == state.CurrentSerial {
		return errors.New("rotated certificate reused current serial")
	}
	if leaf.NotBefore.After(now.Add(5*time.Minute)) || leaf.NotAfter.Before(now.Add(24*time.Hour)) || leaf.NotAfter.After(now.Add(366*24*time.Hour)) {
		return errors.New("rotated certificate validity is unreasonable")
	}
	if response.GetCertificateExpiresAtUnixMs() != 0 && response.GetCertificateExpiresAtUnixMs() != leaf.NotAfter.UnixMilli() {
		return errors.New("certificate expiry metadata mismatch")
	}
	publicDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	certPublicDER, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if !strings.EqualFold(hex.EncodeToString(publicDER), hex.EncodeToString(certPublicDER)) {
		return errors.New("rotated certificate public key mismatch")
	}
	caPEM, err := os.ReadFile(m.options.CAFile)
	if err != nil {
		return err
	}
	if supplied := response.GetCaCertificatePem(); len(supplied) > 0 {
		localCA, _, parseErr := parseCertificates(caPEM)
		if parseErr != nil {
			return parseErr
		}
		responseCA, _, parseErr := parseCertificates(supplied)
		if parseErr != nil {
			return parseErr
		}
		if hex.EncodeToString(localCA.Raw) != hex.EncodeToString(responseCA.Raw) {
			return errors.New("CA rotation is not supported by this agent capability")
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("invalid rotation CA")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: m.options.NodeID, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("verify rotated certificate: %w", err)
	}
	wantURI := fmt.Sprintf("spiffe://frp-admin/%s/%s", m.options.Role, m.options.NodeID)
	found := false
	for _, uri := range leaf.URIs {
		if uri.String() == wantURI {
			found = true
		}
	}
	if !found {
		return errors.New("rotated certificate role SAN mismatch")
	}
	return m.commit(response.GetCertificatePem(), keyPEM)
}

func (m *Manager) Recover() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recoverUnlocked()
}

func (m *Manager) recoverUnlocked() error {
	b, err := os.ReadFile(m.transactionPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var tx transaction
	if err := json.Unmarshal(b, &tx); err != nil {
		return err
	}
	if err := restoreFile(tx.KeyBackup, m.options.KeyFile); err != nil {
		return err
	}
	if err := restoreFile(tx.CertBackup, m.options.CertFile); err != nil {
		return err
	}
	return m.cleanup(tx)
}

func (m *Manager) LoadKeyPair() (tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return tls.LoadX509KeyPair(m.options.CertFile, m.options.KeyFile)
}

func (m *Manager) commit(certPEM, keyPEM []byte) error {
	if err := rejectSymlink(m.options.CertFile); err != nil {
		return err
	}
	if err := rejectSymlink(m.options.KeyFile); err != nil {
		return err
	}
	certBackup := filepath.Join(m.pkiDir(), "rotation-cert.backup")
	keyBackup := filepath.Join(m.pkiDir(), "rotation-key.backup")
	if err := copyAtomic(m.options.CertFile, certBackup); err != nil {
		return err
	}
	if err := copyAtomic(m.options.KeyFile, keyBackup); err != nil {
		return err
	}
	tx := transaction{CertBackup: certBackup, KeyBackup: keyBackup}
	if err := writeJSON(m.transactionPath(), tx); err != nil {
		return err
	}
	if err := writeAtomic(m.options.KeyFile, keyPEM, 0600); err != nil {
		_ = m.recoverUnlocked()
		return err
	}
	if err := writeAtomic(m.options.CertFile, certPEM, 0600); err != nil {
		_ = m.recoverUnlocked()
		return err
	}
	return m.cleanup(tx)
}

func (m *Manager) cleanup(tx transaction) error {
	for _, path := range []string{m.transactionPath(), m.pendingPath(), filepath.Join(m.pkiDir(), "rotation.csr"), filepath.Join(m.pkiDir(), "rotation-key.pem"), tx.CertBackup, tx.KeyBackup} {
		_ = os.Remove(path)
	}
	return nil
}

func (m *Manager) pkiDir() string      { return filepath.Join(m.options.StateDir, "pki") }
func (m *Manager) pendingPath() string { return filepath.Join(m.pkiDir(), "rotation-pending.json") }
func (m *Manager) transactionPath() string {
	return filepath.Join(m.pkiDir(), "rotation-transaction.json")
}
func (m *Manager) loadPending() (pendingState, error) {
	var value pendingState
	b, err := os.ReadFile(m.pendingPath())
	if err != nil {
		return value, err
	}
	err = json.Unmarshal(b, &value)
	return value, err
}

func loadLeaf(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	certs, _, err := parseCertificates(b)
	return certs, err
}
func parseCertificates(data []byte) (*x509.Certificate, []*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, nil, errors.New("certificate PEM is empty")
	}
	return certs[0], certs[1:], nil
}
func parsePrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key PEM is empty")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	value, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not ECDSA")
	}
	return value, nil
}
func secureDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	if err := rejectSymlink(path); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}
func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe symlink path %s", path)
	}
	return nil
}
func writeJSON(path string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeAtomic(path, b, 0600)
}
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := rejectSymlink(path); err != nil {
		return err
	}
	if err := secureDir(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".secure-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func copyAtomic(source, target string) error {
	b, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return writeAtomic(target, b, 0600)
}
func restoreFile(source, target string) error { return copyAtomic(source, target) }
