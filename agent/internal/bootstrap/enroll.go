package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Options struct {
	Address, ServerName, Token, Role, StateDir, AgentVersion string
	RootCA                                                   []byte
}

func Enroll(ctx context.Context, o Options) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal key: %w", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if len(o.RootCA) > 0 && !pool.AppendCertsFromPEM(o.RootCA) {
		return "", fmt.Errorf("parse enrollment CA")
	}
	conn, err := grpc.NewClient(o.Address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: o.ServerName,
	})))
	if err != nil {
		return "", fmt.Errorf("connect enrollment endpoint: %w", err)
	}
	defer conn.Close()
	host, _ := os.Hostname()
	resp, err := agentv1.NewAgentControlServiceClient(conn).Enroll(ctx, &agentv1.EnrollRequest{
		EnrollmentToken: o.Token, PublicKeyPem: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}),
		Role: parseRole(o.Role), Hostname: host, MachineFingerprint: fingerprint(), AgentVersion: o.AgentVersion,
	})
	if err != nil {
		return "", fmt.Errorf("enroll: %w", err)
	}
	pkiDir := filepath.Join(o.StateDir, "pki")
	if err := os.MkdirAll(o.StateDir, 0700); err != nil {
		return "", err
	}
	if err := os.Chmod(o.StateDir, 0700); err != nil {
		return "", err
	}
	if err := os.MkdirAll(pkiDir, 0700); err != nil {
		return "", err
	}
	files := []struct {
		name string
		data []byte
	}{
		{"client-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})},
		{"client.pem", resp.CertificatePem}, {"ca.pem", resp.CaCertificatePem},
	}
	for _, f := range files {
		if err := writePrivate(filepath.Join(pkiDir, f.name), f.data); err != nil {
			return "", err
		}
	}
	if err := writePrivate(filepath.Join(o.StateDir, "node-id"), []byte(resp.NodeId+"\n")); err != nil {
		return "", err
	}
	return resp.NodeId, nil
}

func writePrivate(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refuse symlink credential path %s", path)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".credential-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func fingerprint() string {
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		return strings.TrimSpace(string(b))
	}
	h, _ := os.Hostname()
	return runtime.GOOS + ":" + runtime.GOARCH + ":" + h
}

func parseRole(role string) agentv1.NodeRole {
	if role == "server" {
		return agentv1.NodeRole_NODE_ROLE_SERVER
	}
	return agentv1.NodeRole_NODE_ROLE_CLIENT
}
