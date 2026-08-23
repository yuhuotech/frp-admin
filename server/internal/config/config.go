package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	HTTP      HTTPConfig      `yaml:"http"`
	GRPC      GRPCConfig      `yaml:"grpc"`
	PKI       PKIConfig       `yaml:"pki"`
	MasterKey MasterKeyConfig `yaml:"masterKey"`
	Database  DatabaseConfig  `yaml:"database"`
	Auth      AuthConfig      `yaml:"auth"`
	Log       LogConfig       `yaml:"log"`
	Bootstrap BootstrapConfig `yaml:"bootstrap"`
	Alerting  AlertingConfig  `yaml:"alerting"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Tasks     TaskConfig      `yaml:"tasks"`
}

type HTTPConfig struct {
	Address string `yaml:"address"`
}

type GRPCConfig struct {
	Address string `yaml:"address"`
}

type PKIConfig struct {
	Directory      string   `yaml:"directory"`
	CACertFile     string   `yaml:"caCertFile"`
	CAKeyFile      string   `yaml:"caKeyFile"`
	ServerCertFile string   `yaml:"serverCertFile"`
	ServerKeyFile  string   `yaml:"serverKeyFile"`
	ServerNames    []string `yaml:"serverNames"`
}
type MasterKeyConfig struct {
	File           string            `yaml:"file"`
	CurrentVersion string            `yaml:"currentVersion"`
	KeyFiles       map[string]string `yaml:"keyFiles"`
}

type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type AuthConfig struct {
	SecureCookies bool          `yaml:"secureCookies"`
	SessionTTL    time.Duration `yaml:"-"`
	SessionTTLRaw string        `yaml:"sessionTTL"`
}

type LogConfig struct {
	Level string `yaml:"level"`
}

type BootstrapConfig struct {
	Token string `yaml:"token"`
}
type AlertingConfig struct {
	WebhookURL            string   `yaml:"webhookURL"`
	WebhookSecretFile     string   `yaml:"webhookSecretFile"`
	WebhookSecret         string   `yaml:"-"`
	AllowedHosts          []string `yaml:"allowedHosts"`
	AllowPrivateAddresses bool     `yaml:"allowPrivateAddresses"`
}
type MetricsConfig struct {
	Address string `yaml:"address"`
}
type TaskConfig struct {
	Timeouts TaskTimeoutConfig `yaml:"timeouts"`
}
type TaskTimeoutConfig struct {
	InspectRaw string        `yaml:"inspect"`
	ServiceRaw string        `yaml:"service"`
	ConfigRaw  string        `yaml:"config"`
	UpgradeRaw string        `yaml:"upgrade"`
	Inspect    time.Duration `yaml:"-"`
	Service    time.Duration `yaml:"-"`
	Config     time.Duration `yaml:"-"`
	Upgrade    time.Duration `yaml:"-"`
}

func Default() Config {
	return Config{
		HTTP:      HTTPConfig{Address: ":8080"},
		GRPC:      GRPCConfig{Address: ":8443"},
		PKI:       PKIConfig{Directory: "./data/pki", ServerNames: []string{"localhost"}},
		MasterKey: MasterKeyConfig{File: "./data/master.key", CurrentVersion: "1"},
		Database:  DatabaseConfig{Driver: "sqlite", DSN: "./data/frp-admin.db"},
		Auth:      AuthConfig{SecureCookies: true, SessionTTL: 7 * 24 * time.Hour, SessionTTLRaw: "168h"},
		Log:       LogConfig{Level: "info"},
		Tasks:     TaskConfig{Timeouts: TaskTimeoutConfig{InspectRaw: "2m", ServiceRaw: "2m", ConfigRaw: "5m", UpgradeRaw: "30m"}},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse config: %w", err)
		}
	}
	if err := override(&cfg); err != nil {
		return Config{}, err
	}
	if cfg.Auth.SessionTTLRaw != "" {
		ttl, err := time.ParseDuration(cfg.Auth.SessionTTLRaw)
		if err != nil {
			return Config{}, fmt.Errorf("auth.sessionTTL: %w", err)
		}
		cfg.Auth.SessionTTL = ttl
	}
	if cfg.Auth.SessionTTL <= 0 {
		return Config{}, errors.New("auth.sessionTTL must be positive")
	}
	for name, pair := range map[string]struct {
		raw    string
		target *time.Duration
	}{"inspect": {cfg.Tasks.Timeouts.InspectRaw, &cfg.Tasks.Timeouts.Inspect}, "service": {cfg.Tasks.Timeouts.ServiceRaw, &cfg.Tasks.Timeouts.Service}, "config": {cfg.Tasks.Timeouts.ConfigRaw, &cfg.Tasks.Timeouts.Config}, "upgrade": {cfg.Tasks.Timeouts.UpgradeRaw, &cfg.Tasks.Timeouts.Upgrade}} {
		v, err := time.ParseDuration(pair.raw)
		if err != nil || v < time.Second || v > 24*time.Hour {
			return Config{}, fmt.Errorf("tasks.timeouts.%s must be between 1s and 24h", name)
		}
		*pair.target = v
	}
	switch cfg.Database.Driver {
	case "sqlite", "mysql", "postgres":
	default:
		return Config{}, fmt.Errorf("unsupported database driver %q", cfg.Database.Driver)
	}
	if cfg.Database.DSN == "" {
		return Config{}, errors.New("database.dsn is required")
	}
	if cfg.GRPC.Address == "" {
		return Config{}, errors.New("grpc.address is required")
	}
	if cfg.MasterKey.File == "" {
		return Config{}, errors.New("masterKey.file is required")
	}
	if cfg.Alerting.WebhookURL != "" && cfg.Alerting.WebhookSecret == "" {
		return Config{}, errors.New("alerting.webhookSecretFile is required when webhookURL is configured")
	}
	if cfg.Alerting.WebhookURL != "" {
		u, parseErr := url.Parse(cfg.Alerting.WebhookURL)
		if parseErr != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return Config{}, errors.New("alerting.webhookURL must be an HTTPS URL without userinfo or fragment")
		}
		if cfg.Alerting.AllowPrivateAddresses && len(cfg.Alerting.AllowedHosts) == 0 {
			return Config{}, errors.New("alerting.allowedHosts is required when private webhook addresses are enabled")
		}
		if len(cfg.Alerting.AllowedHosts) > 0 && !containsHost(cfg.Alerting.AllowedHosts, u.Hostname()) {
			return Config{}, errors.New("alerting.webhookURL host must be listed in alerting.allowedHosts")
		}
	}
	external := []string{cfg.PKI.CACertFile, cfg.PKI.CAKeyFile, cfg.PKI.ServerCertFile, cfg.PKI.ServerKeyFile}
	externalSet := 0
	for _, v := range external {
		if v != "" {
			externalSet++
		}
	}
	if externalSet != 0 && externalSet != len(external) {
		return Config{}, errors.New("all external PKI files must be configured together")
	}
	if externalSet == 0 && cfg.PKI.Directory == "" {
		return Config{}, errors.New("pki.directory or all external PKI files are required")
	}
	return cfg, nil
}

func override(cfg *Config) error {
	if v := os.Getenv("FRP_ADMIN_HTTP_ADDRESS"); v != "" {
		cfg.HTTP.Address = v
	}
	if v := os.Getenv("FRP_ADMIN_GRPC_ADDRESS"); v != "" {
		cfg.GRPC.Address = v
	}
	if v := os.Getenv("FRP_ADMIN_PKI_DIRECTORY"); v != "" {
		cfg.PKI.Directory = v
	}
	if v := os.Getenv("FRP_ADMIN_PKI_CA_CERT_FILE"); v != "" {
		cfg.PKI.CACertFile = v
	}
	if v := os.Getenv("FRP_ADMIN_PKI_CA_KEY_FILE"); v != "" {
		cfg.PKI.CAKeyFile = v
	}
	if v := os.Getenv("FRP_ADMIN_PKI_SERVER_CERT_FILE"); v != "" {
		cfg.PKI.ServerCertFile = v
	}
	if v := os.Getenv("FRP_ADMIN_PKI_SERVER_KEY_FILE"); v != "" {
		cfg.PKI.ServerKeyFile = v
	}
	if v := os.Getenv("FRP_ADMIN_MASTER_KEY_FILE"); v != "" {
		cfg.MasterKey.File = v
	}
	if v := os.Getenv("FRP_ADMIN_DATABASE_DRIVER"); v != "" {
		cfg.Database.Driver = v
	}
	dsnValue, dsnFile := os.Getenv("FRP_ADMIN_DATABASE_DSN"), os.Getenv("FRP_ADMIN_DATABASE_DSN_FILE")
	if dsnValue != "" && dsnFile != "" {
		return errors.New("FRP_ADMIN_DATABASE_DSN and FRP_ADMIN_DATABASE_DSN_FILE are mutually exclusive")
	}
	if dsnFile != "" {
		data, e := os.ReadFile(dsnFile)
		if e != nil {
			return fmt.Errorf("read database DSN file: %w", e)
		}
		cfg.Database.DSN = strings.TrimSpace(string(data))
	} else if v := dsnValue; v != "" {
		cfg.Database.DSN = v
	}
	bootstrapValue, bootstrapFile := os.Getenv("FRP_ADMIN_BOOTSTRAP_TOKEN"), os.Getenv("FRP_ADMIN_BOOTSTRAP_TOKEN_FILE")
	if bootstrapValue != "" && bootstrapFile != "" {
		return errors.New("FRP_ADMIN_BOOTSTRAP_TOKEN and FRP_ADMIN_BOOTSTRAP_TOKEN_FILE are mutually exclusive")
	}
	if bootstrapFile != "" {
		data, e := os.ReadFile(bootstrapFile)
		if e != nil {
			return fmt.Errorf("read bootstrap token file: %w", e)
		}
		cfg.Bootstrap.Token = strings.TrimSpace(string(data))
	} else if v := bootstrapValue; v != "" {
		cfg.Bootstrap.Token = v
	}
	if v := os.Getenv("FRP_ADMIN_LOG_LEVEL"); v != "" {
		cfg.Log.Level = v
	}
	if v := os.Getenv("FRP_ADMIN_ALERT_WEBHOOK_URL"); v != "" {
		cfg.Alerting.WebhookURL = v
	}
	if v := os.Getenv("FRP_ADMIN_ALERT_WEBHOOK_SECRET_FILE"); v != "" {
		cfg.Alerting.WebhookSecretFile = v
	}
	if v := os.Getenv("FRP_ADMIN_ALERT_WEBHOOK_ALLOWED_HOSTS"); v != "" {
		cfg.Alerting.AllowedHosts = strings.Split(v, ",")
	}
	if v := os.Getenv("FRP_ADMIN_ALERT_WEBHOOK_ALLOW_PRIVATE_ADDRESSES"); v != "" {
		parsed, e := strconv.ParseBool(v)
		if e != nil {
			return fmt.Errorf("parse FRP_ADMIN_ALERT_WEBHOOK_ALLOW_PRIVATE_ADDRESSES: %w", e)
		}
		cfg.Alerting.AllowPrivateAddresses = parsed
	}
	if v := os.Getenv("FRP_ADMIN_METRICS_ADDRESS"); v != "" {
		cfg.Metrics.Address = v
	}
	if v := os.Getenv("FRP_ADMIN_TASK_TIMEOUT_INSPECT"); v != "" {
		cfg.Tasks.Timeouts.InspectRaw = v
	}
	if v := os.Getenv("FRP_ADMIN_TASK_TIMEOUT_SERVICE"); v != "" {
		cfg.Tasks.Timeouts.ServiceRaw = v
	}
	if v := os.Getenv("FRP_ADMIN_TASK_TIMEOUT_CONFIG"); v != "" {
		cfg.Tasks.Timeouts.ConfigRaw = v
	}
	if v := os.Getenv("FRP_ADMIN_TASK_TIMEOUT_UPGRADE"); v != "" {
		cfg.Tasks.Timeouts.UpgradeRaw = v
	}
	if cfg.Alerting.WebhookSecretFile != "" {
		data, e := os.ReadFile(cfg.Alerting.WebhookSecretFile)
		if e != nil {
			return fmt.Errorf("read alert webhook secret file: %w", e)
		}
		cfg.Alerting.WebhookSecret = strings.TrimSpace(string(data))
	}
	if v := os.Getenv("FRP_ADMIN_AUTH_SESSION_TTL"); v != "" {
		cfg.Auth.SessionTTLRaw = v
	}
	if v := os.Getenv("FRP_ADMIN_AUTH_SECURE_COOKIES"); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			cfg.Auth.SecureCookies = parsed
		}
	}
	return nil
}

func containsHost(allowedHosts []string, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, allowed := range allowedHosts {
		if host == strings.ToLower(strings.TrimSuffix(strings.TrimSpace(allowed), ".")) {
			return true
		}
	}
	return false
}
