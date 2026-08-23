package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ServerURL string  `yaml:"serverURL"`
	Role      string  `yaml:"role"`
	NodeID    string  `yaml:"nodeID"`
	StateDir  string  `yaml:"stateDir"`
	TLS       TLS     `yaml:"tls"`
	FRP       FRP     `yaml:"frp"`
	Channel   Channel `yaml:"channel"`
	Upgrade   Upgrade `yaml:"upgrade"`
}

type TLS struct {
	CAFile     string `yaml:"caFile"`
	CertFile   string `yaml:"certFile"`
	KeyFile    string `yaml:"keyFile"`
	ServerName string `yaml:"serverName"`
}

type FRP struct {
	ServiceName      string   `yaml:"serviceName"`
	LaunchdPlistPath string   `yaml:"launchdPlistPath"`
	BinaryPath       string   `yaml:"binaryPath"`
	ConfigPath       string   `yaml:"configPath"`
	HelperSocket     string   `yaml:"helperSocket"`
	AdminAPI         AdminAPI `yaml:"adminAPI"`
}

type AdminAPI struct {
	Endpoint         string        `yaml:"endpoint"`
	Username         string        `yaml:"username"`
	PasswordInline   string        `yaml:"password"`
	PasswordFile     string        `yaml:"passwordFile"`
	Password         string        `yaml:"-"`
	Timeout          time.Duration `yaml:"timeout"`
	MaxResponseBytes int64         `yaml:"maxResponseBytes"`
}

type Channel struct {
	HeartbeatInterval time.Duration `yaml:"heartbeatInterval"`
	ReconnectMin      time.Duration `yaml:"reconnectMin"`
	ReconnectMax      time.Duration `yaml:"reconnectMax"`
}

type Upgrade struct {
	AllowedHosts     []string `yaml:"allowedHosts"`
	MaxArtifactBytes int64    `yaml:"maxArtifactBytes"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	c := Config{}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	c.defaults()
	if err := c.loadAdminAPIPassword(); err != nil {
		return Config{}, err
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c *Config) defaults() {
	if c.StateDir == "" {
		c.StateDir = "/var/lib/frp-agent"
	}
	if c.Channel.HeartbeatInterval == 0 {
		c.Channel.HeartbeatInterval = 15 * time.Second
	}
	if c.Channel.ReconnectMin == 0 {
		c.Channel.ReconnectMin = time.Second
	}
	if c.Channel.ReconnectMax == 0 {
		c.Channel.ReconnectMax = time.Minute
	}
	if c.TLS.CAFile == "" {
		c.TLS.CAFile = filepath.Join(c.StateDir, "pki", "ca.pem")
	}
	if c.TLS.CertFile == "" {
		c.TLS.CertFile = filepath.Join(c.StateDir, "pki", "client.pem")
	}
	if c.TLS.KeyFile == "" {
		c.TLS.KeyFile = filepath.Join(c.StateDir, "pki", "client-key.pem")
	}
	if len(c.Upgrade.AllowedHosts) == 0 {
		c.Upgrade.AllowedHosts = []string{"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
	}
	if c.Upgrade.MaxArtifactBytes == 0 {
		c.Upgrade.MaxArtifactBytes = 256 << 20
	}
	if c.FRP.AdminAPI.Endpoint == "" {
		port := "7400"
		if c.Role == "server" {
			port = "7500"
		}
		c.FRP.AdminAPI.Endpoint = "http://127.0.0.1:" + port
	}
	if c.FRP.AdminAPI.Timeout == 0 {
		c.FRP.AdminAPI.Timeout = 3 * time.Second
	}
	if c.FRP.AdminAPI.MaxResponseBytes == 0 {
		c.FRP.AdminAPI.MaxResponseBytes = 1 << 20
	}
}

func (c Config) Validate() error {
	if c.ServerURL == "" {
		return errors.New("serverURL is required")
	}
	if c.Role != "client" && c.Role != "server" {
		return errors.New("role must be client or server")
	}
	if c.FRP.ServiceName == "" {
		return errors.New("frp.serviceName is required")
	}
	if c.FRP.BinaryPath == "" || c.FRP.ConfigPath == "" {
		return errors.New("frp.binaryPath and frp.configPath are required")
	}
	if !filepath.IsAbs(c.FRP.BinaryPath) || !filepath.IsAbs(c.FRP.ConfigPath) {
		return errors.New("frp.binaryPath and frp.configPath must be absolute")
	}
	if c.FRP.HelperSocket != "" && c.FRP.HelperSocket != "/run/frp-agent-helper.sock" {
		return errors.New("frp.helperSocket must be /run/frp-agent-helper.sock when configured")
	}
	if err := validateServiceIdentity(c.FRP.ServiceName, c.FRP.LaunchdPlistPath, c.Role); err != nil {
		return err
	}
	if c.Channel.ReconnectMin > c.Channel.ReconnectMax {
		return errors.New("channel.reconnectMin must not exceed reconnectMax")
	}
	if c.Upgrade.MaxArtifactBytes <= 0 {
		return errors.New("upgrade.maxArtifactBytes must be positive")
	}
	if c.Upgrade.MaxArtifactBytes > 4<<30 {
		return errors.New("upgrade.maxArtifactBytes must not exceed 4 GiB")
	}
	if err := validateAdminAPI(c.FRP.AdminAPI); err != nil {
		return err
	}
	if _, err := c.GRPCTarget(); err != nil {
		return err
	}
	return nil
}

func validateServiceIdentity(serviceName, launchdPlistPath, role string) error {
	if serviceName == "" || strings.HasPrefix(serviceName, "-") || strings.ContainsAny(serviceName, "/\\\t\r\n ") {
		return errors.New("frp.serviceName is not a valid service identifier")
	}
	if runtime.GOOS == "linux" {
		expectedService := "frpc.service"
		if role == "server" {
			expectedService = "frps.service"
		}
		if serviceName != expectedService {
			return fmt.Errorf("frp.serviceName must be %s for role %s", expectedService, role)
		}
		if launchdPlistPath != "" {
			return errors.New("frp.launchdPlistPath is only supported on macOS")
		}
		return nil
	}
	if runtime.GOOS == "darwin" {
		if launchdPlistPath != "" && !filepath.IsAbs(launchdPlistPath) {
			return errors.New("frp.launchdPlistPath must be absolute")
		}
		return nil
	}
	return fmt.Errorf("service lifecycle is unsupported on %s", runtime.GOOS)
}

func validateAdminAPI(value AdminAPI) error {
	u, err := url.Parse(value.Endpoint)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		return errors.New("frp.adminAPI.endpoint must be an HTTP loopback URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("frp.adminAPI.endpoint must not include credentials, path, query, or fragment")
	}
	host := net.ParseIP(u.Hostname())
	if host == nil || !host.IsLoopback() {
		return errors.New("frp.adminAPI.endpoint must use a literal loopback address")
	}
	if value.Timeout <= 0 || value.Timeout > 30*time.Second {
		return errors.New("frp.adminAPI.timeout must be between 0 and 30 seconds")
	}
	if value.MaxResponseBytes < 1024 || value.MaxResponseBytes > 16<<20 {
		return errors.New("frp.adminAPI.maxResponseBytes must be between 1 KiB and 16 MiB")
	}
	if value.PasswordFile != "" && !filepath.IsAbs(value.PasswordFile) {
		return errors.New("frp.adminAPI.passwordFile must be absolute")
	}
	if value.Username != "" && value.Password == "" {
		return errors.New("frp.adminAPI.passwordFile must contain a password when username is configured")
	}
	return nil
}

func (c *Config) loadAdminAPIPassword() error {
	if c.FRP.AdminAPI.PasswordInline != "" && c.FRP.AdminAPI.PasswordFile != "" {
		return errors.New("frp.adminAPI.password and passwordFile are mutually exclusive")
	}
	if c.FRP.AdminAPI.PasswordInline != "" {
		return errors.New("frp.adminAPI.password is not supported; use passwordFile")
	}
	if c.FRP.AdminAPI.PasswordFile == "" {
		return nil
	}
	info, err := os.Lstat(c.FRP.AdminAPI.PasswordFile)
	if err != nil {
		return fmt.Errorf("frp.adminAPI.passwordFile: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("frp.adminAPI.passwordFile must be a regular file, not a symlink")
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("frp.adminAPI.passwordFile must not be accessible by group or other")
	}
	if info.Size() > 4096 {
		return errors.New("frp.adminAPI.passwordFile must not exceed 4 KiB")
	}
	data, err := os.ReadFile(c.FRP.AdminAPI.PasswordFile)
	if err != nil {
		return fmt.Errorf("read frp.adminAPI.passwordFile: %w", err)
	}
	password := strings.TrimRight(string(data), "\r\n")
	if password == "" {
		return errors.New("frp.adminAPI.passwordFile must not be empty")
	}
	if strings.IndexByte(password, 0) >= 0 {
		return errors.New("frp.adminAPI.passwordFile must not contain NUL bytes")
	}
	c.FRP.AdminAPI.Password = password
	return nil
}

func (c Config) GRPCTarget() (string, error) {
	if !strings.Contains(c.ServerURL, "://") {
		return c.ServerURL, nil
	}
	u, err := url.Parse(c.ServerURL)
	if err != nil || u.Host == "" {
		return "", errors.New("serverURL is invalid")
	}
	if u.Scheme != "https" {
		return "", errors.New("serverURL URL scheme must be https")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("serverURL must not include a path")
	}
	return u.Host, nil
}
