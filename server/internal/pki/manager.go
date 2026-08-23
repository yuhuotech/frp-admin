package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/config"
)

type Manager struct {
	ca     *x509.Certificate
	caKey  crypto.Signer
	caPEM  []byte
	server tls.Certificate
	now    func() time.Time
}

func LoadOrCreate(cfg config.PKIConfig) (*Manager, error) {
	caCert, caKey, serverCert, serverKey := cfg.CACertFile, cfg.CAKeyFile, cfg.ServerCertFile, cfg.ServerKeyFile
	external := caCert != "" || caKey != "" || serverCert != "" || serverKey != ""
	if caCert == "" && caKey == "" && serverCert == "" && serverKey == "" {
		caCert = filepath.Join(cfg.Directory, "ca.crt")
		caKey = filepath.Join(cfg.Directory, "ca.key")
		serverCert = filepath.Join(cfg.Directory, "server.crt")
		serverKey = filepath.Join(cfg.Directory, "server.key")
	}
	paths := []string{caCert, caKey, serverCert, serverKey}
	exists := 0
	for _, p := range paths {
		if _, e := os.Stat(p); e == nil {
			exists++
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
	}
	if exists != 0 && exists != len(paths) {
		return nil, errors.New("incomplete PKI file set; refusing to replace trust material")
	}
	if exists == 0 {
		if external {
			return nil, errors.New("configured external PKI files do not exist")
		}
		if cfg.Directory == "" {
			return nil, errors.New("external PKI files do not exist")
		}
		if err := generate(paths, cfg.ServerNames); err != nil {
			return nil, err
		}
	}
	caPEM, e := os.ReadFile(caCert)
	if e != nil {
		return nil, e
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" {
		return nil, errors.New("invalid CA certificate PEM")
	}
	ca, e := x509.ParseCertificate(caBlock.Bytes)
	if e != nil {
		return nil, e
	}
	if !ca.IsCA {
		return nil, errors.New("configured CA certificate is not a CA")
	}
	key, e := readSigner(caKey)
	if e != nil {
		return nil, e
	}
	if !publicKeysEqual(ca.PublicKey, key.Public()) {
		return nil, errors.New("CA certificate and key do not match")
	}
	server, e := tls.LoadX509KeyPair(serverCert, serverKey)
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(server.Certificate[0])
	if e != nil {
		return nil, e
	}
	if e = leaf.CheckSignatureFrom(ca); e != nil {
		return nil, fmt.Errorf("server certificate is not signed by Agent CA: %w", e)
	}
	if m := time.Now(); m.Before(leaf.NotBefore) || m.After(leaf.NotAfter) {
		return nil, errors.New("server certificate is not currently valid")
	}
	return &Manager{ca: ca, caKey: key, caPEM: caPEM, server: server, now: time.Now}, nil
}

func (m *Manager) TLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(m.ca)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{m.server}, ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven}
}
func (m *Manager) CAPEM() []byte { return append([]byte(nil), m.caPEM...) }

func (m *Manager) SignClient(publicKeyPEM []byte, nodeID string, ttl time.Duration) ([]byte, time.Time, error) {
	block, rest := pem.Decode(publicKeyPEM)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return nil, time.Time{}, errors.New("public key must be one PKIX PUBLIC KEY PEM block")
	}
	pub, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return nil, time.Time{}, fmt.Errorf("parse public key: %w", e)
	}
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return nil, time.Time{}, errors.New("RSA public key must be at least 2048 bits")
		}
	case *ecdsa.PublicKey:
		if key.Curve.Params().BitSize < 256 {
			return nil, time.Time{}, errors.New("ECDSA public key curve is too small")
		}
	case ed25519.PublicKey:
	default:
		return nil, time.Time{}, errors.New("unsupported public key algorithm")
	}
	now := m.now().UTC()
	expires := now.Add(ttl).Truncate(time.Second)
	uri, _ := url.Parse("spiffe://frp-admin/node/" + nodeID)
	serial, e := randomSerial()
	if e != nil {
		return nil, time.Time{}, e
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: nodeID}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, DNSNames: []string{nodeID}, URIs: []*url.URL{uri}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, template, m.ca, pub, m.caKey)
	if e != nil {
		return nil, time.Time{}, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), expires, nil
}

func (m *Manager) SignClientCSR(csrPEM []byte, nodeID, role string, ttl time.Duration) ([]byte, time.Time, error) {
	if len(csrPEM) == 0 || len(csrPEM) > 64<<10 {
		return nil, time.Time{}, errors.New("CSR must contain 1-65536 bytes")
	}
	if role != "client" && role != "server" {
		return nil, time.Time{}, errors.New("certificate role must be client or server")
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE REQUEST" {
		return nil, time.Time{}, errors.New("CSR must be one CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse CSR: %w", err)
	}
	if err = csr.CheckSignature(); err != nil {
		return nil, time.Time{}, errors.New("CSR signature is invalid")
	}
	if err = validatePublicKey(csr.PublicKey); err != nil {
		return nil, time.Time{}, err
	}
	now := m.now().UTC()
	expires := now.Add(ttl).Truncate(time.Second)
	identity, _ := url.Parse("spiffe://frp-admin/" + role + "/" + nodeID)
	serial, err := randomSerial()
	if err != nil {
		return nil, time.Time{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: nodeID},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              expires,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:              []string{nodeID},
		URIs:                  []*url.URL{identity},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, m.ca, csr.PublicKey, m.caKey)
	if err != nil {
		return nil, time.Time{}, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), expires, nil
}

func validatePublicKey(pub any) error {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return errors.New("RSA public key must be at least 2048 bits")
		}
	case *ecdsa.PublicKey:
		if key.Curve == nil || key.Curve.Params().BitSize < 256 {
			return errors.New("ECDSA public key curve is too small")
		}
	case ed25519.PublicKey:
	default:
		return errors.New("unsupported public key algorithm")
	}
	return nil
}

func generate(paths []string, names []string) error {
	dir := filepath.Dir(paths[0])
	if e := os.MkdirAll(dir, 0o700); e != nil {
		return e
	}
	for _, p := range paths[1:] {
		if filepath.Dir(p) != dir {
			return errors.New("generated PKI files must share pki.directory")
		}
	}
	now := time.Now().UTC()
	caPub, caPriv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	serial, e := randomSerial()
	if e != nil {
		return e
	}
	caTpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "frp-admin Agent CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	caDER, e := x509.CreateCertificate(rand.Reader, caTpl, caTpl, caPub, caPriv)
	if e != nil {
		return e
	}
	serverPub, serverPriv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	serial, e = randomSerial()
	if e != nil {
		return e
	}
	serverTpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "frp-admin-server"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	allNames := append([]string{"localhost"}, names...)
	seen := map[string]bool{}
	for _, name := range allNames {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if ip := net.ParseIP(name); ip != nil {
			serverTpl.IPAddresses = append(serverTpl.IPAddresses, ip)
		} else {
			serverTpl.DNSNames = append(serverTpl.DNSNames, name)
		}
	}
	serverDER, e := x509.CreateCertificate(rand.Reader, serverTpl, caTpl, serverPub, caPriv)
	if e != nil {
		return e
	}
	caKeyDER, e := x509.MarshalPKCS8PrivateKey(caPriv)
	if e != nil {
		return e
	}
	serverKeyDER, e := x509.MarshalPKCS8PrivateKey(serverPriv)
	if e != nil {
		return e
	}
	files := [][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER})}
	for i, p := range paths {
		if e := atomicWrite(p, files[i]); e != nil {
			return e
		}
	}
	return nil
}
func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if e := os.WriteFile(tmp, data, 0o600); e != nil {
		return e
	}
	if e := os.Chmod(tmp, 0o600); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
func readSigner(path string) (crypto.Signer, error) {
	data, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 {
		return nil, errors.New("invalid private key PEM")
	}
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		if candidate, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes); rsaErr == nil {
			key = candidate
		} else if candidate, ecErr := x509.ParseECPrivateKey(block.Bytes); ecErr == nil {
			key = candidate
		} else {
			return nil, e
		}
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key is not a signer")
	}
	return signer, nil
}
func publicKeysEqual(a, b any) bool {
	aa, e := x509.MarshalPKIXPublicKey(a)
	if e != nil {
		return false
	}
	bb, e := x509.MarshalPKIXPublicKey(b)
	return e == nil && string(aa) == string(bb)
}
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
