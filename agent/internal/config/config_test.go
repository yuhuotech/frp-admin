package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte("serverURL: localhost:8443\nrole: client\nfrp:\n  serviceName: frpc.service\n  binaryPath: /usr/local/bin/frpc\n  configPath: /etc/frp/frpc.toml\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Channel.HeartbeatInterval != 15*time.Second || c.TLS.CertFile != "/var/lib/frp-agent/pki/client.pem" {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if c.Upgrade.MaxArtifactBytes != 256<<20 || len(c.Upgrade.AllowedHosts) != 3 {
		t.Fatalf("upgrade defaults not applied: %+v", c.Upgrade)
	}
	if c.FRP.AdminAPI.Endpoint != "http://127.0.0.1:7400" || c.FRP.AdminAPI.Timeout != 3*time.Second || c.FRP.AdminAPI.MaxResponseBytes != 1<<20 {
		t.Fatalf("Admin API defaults not applied: %+v", c.FRP.AdminAPI)
	}
}

func TestRejectNonLoopbackAdminAPI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	data := []byte("serverURL: localhost:8443\nrole: server\nfrp:\n  serviceName: frps.service\n  binaryPath: /usr/local/bin/frps\n  configPath: /etc/frp/frps.toml\n  adminAPI:\n    endpoint: http://example.com:7500\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected non-loopback Admin API to be rejected")
	}
}

func TestRejectAdminAPICredentialsInURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	data := []byte("serverURL: localhost:8443\nrole: client\nfrp:\n  serviceName: frpc.service\n  binaryPath: /usr/local/bin/frpc\n  configPath: /etc/frp/frpc.toml\n  adminAPI:\n    endpoint: http://user:secret@127.0.0.1:7400\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected URL credentials to be rejected")
	}
}

func TestLoadAdminAPIPasswordFile(t *testing.T) {
	dir := t.TempDir()
	passwordPath := filepath.Join(dir, "admin-password")
	if err := os.WriteFile(passwordPath, []byte("local-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent.yaml")
	data := []byte("serverURL: localhost:8443\nrole: client\nfrp:\n  serviceName: frpc.service\n  binaryPath: /opt/frp/bin/frpc\n  configPath: /etc/frp/frpc.toml\n  adminAPI:\n    passwordFile: " + passwordPath + "\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil || cfg.FRP.AdminAPI.Password != "local-secret" {
		t.Fatalf("password loaded=%q err=%v", cfg.FRP.AdminAPI.Password, err)
	}
}

func TestRejectInlineAdminAPIPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	data := []byte("serverURL: localhost:8443\nrole: client\nfrp:\n  serviceName: frpc.service\n  binaryPath: /opt/frp/bin/frpc\n  configPath: /etc/frp/frpc.toml\n  adminAPI:\n    username: runtime-reader\n    password: inline-secret\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected inline Admin API password to be rejected")
	}
}

func TestRejectAdminAPIUsernameWithoutPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	data := []byte("serverURL: localhost:8443\nrole: client\nfrp:\n  serviceName: frpc.service\n  binaryPath: /opt/frp/bin/frpc\n  configPath: /etc/frp/frpc.toml\n  adminAPI:\n    username: runtime-reader\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected Admin API username without a password to be rejected")
	}
}

func TestRejectUnsafeAdminAPIPasswordFiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(string) error
	}{
		{name: "permissions", make: func(path string) error { return os.WriteFile(path, []byte("secret"), 0644) }},
		{name: "symlink", make: func(path string) error {
			target := path + ".target"
			if err := os.WriteFile(target, []byte("secret"), 0600); err != nil {
				return err
			}
			return os.Symlink(target, path)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			passwordPath := filepath.Join(dir, "password")
			if err := tc.make(passwordPath); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(dir, "agent.yaml")
			data := []byte("serverURL: localhost:8443\nrole: client\nfrp:\n  serviceName: frpc.service\n  binaryPath: /opt/frp/bin/frpc\n  configPath: /etc/frp/frpc.toml\n  adminAPI:\n    passwordFile: " + passwordPath + "\n")
			if err := os.WriteFile(configPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(configPath); err == nil {
				t.Fatal("expected unsafe password file to be rejected")
			}
		})
	}
}

func TestRejectInvalidAdminAPIPasswordContents(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "empty", data: []byte("\r\n")},
		{name: "nul", data: []byte("secret\x00suffix")},
		{name: "too-large", data: make([]byte, 4097)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			passwordPath := filepath.Join(dir, "password")
			if err := os.WriteFile(passwordPath, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(dir, "agent.yaml")
			data := []byte("serverURL: localhost:8443\nrole: client\nfrp:\n  serviceName: frpc.service\n  binaryPath: /opt/frp/bin/frpc\n  configPath: /etc/frp/frpc.toml\n  adminAPI:\n    username: runtime-reader\n    passwordFile: " + passwordPath + "\n")
			if err := os.WriteFile(configPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(configPath); err == nil {
				t.Fatal("expected invalid password contents to be rejected")
			}
		})
	}
}

func TestRejectServicePath(t *testing.T) {
	c := Config{ServerURL: "localhost:8443", Role: "client", FRP: FRP{ServiceName: "../ssh.service", BinaryPath: "/bin/frpc", ConfigPath: "/etc/frp/frpc.toml"}}
	if err := c.Validate(); err == nil {
		t.Fatal("expected unsafe service name to be rejected")
	}
}

func TestRejectSystemdOptionAsService(t *testing.T) {
	c := Config{ServerURL: "localhost:8443", Role: "client", FRP: FRP{ServiceName: "--system", BinaryPath: "/bin/frpc", ConfigPath: "/etc/frp/frpc.toml"}}
	if err := c.Validate(); err == nil {
		t.Fatal("expected systemd option to be rejected")
	}
}

func TestRejectServiceThatDoesNotMatchRole(t *testing.T) {
	c := Config{ServerURL: "localhost:8443", Role: "client", FRP: FRP{ServiceName: "frps.service", BinaryPath: "/bin/frpc", ConfigPath: "/etc/frp/frpc.toml"}}
	if err := c.Validate(); err == nil {
		t.Fatal("expected role and service mismatch to be rejected")
	}
}

func TestGRPCTargetFromHTTPSURL(t *testing.T) {
	c := Config{ServerURL: "https://admin.example.com:8443"}
	target, err := c.GRPCTarget()
	if err != nil || target != "admin.example.com:8443" {
		t.Fatalf("target=%q err=%v", target, err)
	}
}
