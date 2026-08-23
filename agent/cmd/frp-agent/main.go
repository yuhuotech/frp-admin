package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/frp-admin/frp-admin/agent/internal/bootstrap"
	"github.com/frp-admin/frp-admin/agent/internal/certmgr"
	channelclient "github.com/frp-admin/frp-admin/agent/internal/channel"
	"github.com/frp-admin/frp-admin/agent/internal/config"
	"github.com/frp-admin/frp-admin/agent/internal/configmgr"
	"github.com/frp-admin/frp-admin/agent/internal/executor"
	"github.com/frp-admin/frp-admin/agent/internal/frpadmin"
	"github.com/frp-admin/frp-admin/agent/internal/inventory"
	"github.com/frp-admin/frp-admin/agent/internal/journal"
	"github.com/frp-admin/frp-admin/agent/internal/managementcap"
	"github.com/frp-admin/frp-admin/agent/internal/remediation"
	"github.com/frp-admin/frp-admin/agent/internal/roothelper"
	"github.com/frp-admin/frp-admin/agent/internal/securitycheck"
	"github.com/frp-admin/frp-admin/agent/internal/service"
	"github.com/frp-admin/frp-admin/agent/internal/upgrader"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "/etc/frp-agent/agent.yaml", "configuration file")
	enrollToken := flag.String("enroll-token", "", "one-time enrollment token")
	enrollCA := flag.String("enroll-ca", "", "PEM CA used to authenticate the enrollment endpoint")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *enrollToken != "" {
		target, err := cfg.GRPCTarget()
		if err != nil {
			fatal(err)
		}
		caPath := *enrollCA
		if caPath == "" {
			caPath = cfg.TLS.CAFile
		}
		var rootCA []byte
		if caPath != "" {
			if b, readErr := os.ReadFile(caPath); readErr == nil {
				rootCA = b
			} else if *enrollCA != "" {
				fatal(fmt.Errorf("read enrollment CA: %w", readErr))
			}
		}
		id, err := bootstrap.Enroll(ctx, bootstrap.Options{Address: target, ServerName: cfg.TLS.ServerName,
			Token: *enrollToken, Role: cfg.Role, StateDir: cfg.StateDir, AgentVersion: version, RootCA: rootCA})
		if err != nil {
			fatal(err)
		}
		fmt.Println(id)
		return
	}
	if cfg.NodeID == "" {
		if b, readErr := os.ReadFile(filepath.Join(cfg.StateDir, "node-id")); readErr == nil {
			cfg.NodeID = strings.TrimSpace(string(b))
		}
	}
	if cfg.NodeID == "" {
		fatal(fmt.Errorf("nodeID is required after enrollment"))
	}
	if err := os.MkdirAll(filepath.Join(cfg.StateDir, "journal"), 0700); err != nil {
		fatal(err)
	}
	j, err := journal.Open(filepath.Join(cfg.StateDir, "journal", "commands.db"), 1000)
	if err != nil {
		fatal(err)
	}
	defer j.Close()
	services := service.NewSystemd(cfg.FRP.ServiceName, cfg.FRP.BinaryPath, cfg.FRP.ConfigPath, cfg.Role)
	var helper *roothelper.Client
	if cfg.FRP.HelperSocket != "" {
		helper = &roothelper.Client{SocketPath: cfg.FRP.HelperSocket}
	}
	var serviceManager service.Manager = services
	var configLifecycle configmgr.Lifecycle = services
	var upgradeLifecycle upgrader.Lifecycle = services
	if runtime.GOOS == "linux" && helper != nil {
		privilegedLifecycle := roothelper.NewServiceLifecycle(services, helper)
		serviceManager = privilegedLifecycle
		configLifecycle = privilegedLifecycle
		upgradeLifecycle = privilegedLifecycle
	}
	localSecurityChecks := securitycheck.New(cfg.Role, cfg.FRP.ConfigPath, cfg.FRP.ServiceName)
	var securityChecks securitycheck.Collector = localSecurityChecks
	if runtime.GOOS == "linux" && cfg.FRP.HelperSocket != "" {
		securityChecks = securitycheck.NewFailover(&roothelper.Client{SocketPath: cfg.FRP.HelperSocket}, localSecurityChecks)
	}
	inv := inventory.New(cfg.FRP.BinaryPath, cfg.FRP.ServiceName, services, securityChecks)
	configs, err := configmgr.New(configmgr.Options{Role: cfg.Role, BinaryPath: cfg.FRP.BinaryPath, ConfigPath: cfg.FRP.ConfigPath,
		StateDir: cfg.StateDir, Verifier: configmgr.CLIVerifier{}, Lifecycle: configLifecycle})
	if err != nil {
		fatal(err)
	}
	upgrades, err := upgrader.New(upgrader.Options{Role: cfg.Role, BinaryPath: cfg.FRP.BinaryPath, ConfigPath: cfg.FRP.ConfigPath,
		StateDir: cfg.StateDir, AllowedHosts: cfg.Upgrade.AllowedHosts, MaxArtifactBytes: cfg.Upgrade.MaxArtifactBytes,
		Downloader: upgrader.HTTPDownloader{}, Runner: upgrader.CLIRunner{}, Lifecycle: upgradeLifecycle})
	if err != nil {
		fatal(err)
	}
	if err := configs.Recover(ctx); err != nil {
		fatal(fmt.Errorf("recover interrupted config transaction: %w", err))
	}
	remediator, err := remediation.New(remediation.Options{Role: cfg.Role, BinaryPath: cfg.FRP.BinaryPath,
		ConfigPath: cfg.FRP.ConfigPath, ServiceName: cfg.FRP.ServiceName, StateDir: cfg.StateDir,
		Configs: configs, Verifier: configmgr.CLIVerifier{}, Inventory: inv, Helper: helper})
	if err != nil {
		fatal(fmt.Errorf("initialize deployment risk remediator: %w", err))
	}
	if err := remediator.Recover(); err != nil {
		fatal(fmt.Errorf("recover interrupted deployment risk repair: %w", err))
	}
	if err := upgrades.Recover(ctx); err != nil {
		fatal(fmt.Errorf("recover interrupted upgrade transaction: %w", err))
	}
	certificates, err := certmgr.New(certmgr.Options{NodeID: cfg.NodeID, Role: cfg.Role, CertFile: cfg.TLS.CertFile,
		KeyFile: cfg.TLS.KeyFile, CAFile: cfg.TLS.CAFile, StateDir: cfg.StateDir})
	if err != nil {
		fatal(err)
	}
	if err := certificates.Recover(); err != nil {
		fatal(fmt.Errorf("recover certificate rotation: %w", err))
	}
	commands := executor.New(j, inv, serviceManager).WithConfigManager(configs).WithUpgrader(upgrades).WithRemediator(remediator)
	runtimeCollector, err := frpadmin.New(cfg.Role, cfg.FRP.AdminAPI)
	if err != nil {
		fatal(fmt.Errorf("initialize frp Admin API collector: %w", err))
	}
	commands.WithRuntimeCollector(runtimeCollector)
	client := channelclient.New(cfg, version, commands).WithCertificateManager(certificates)
	availableCapabilities := baseCapabilities()
	if runtime.GOOS == "linux" && services.Controllable(ctx) == nil {
		availableCapabilities = append(availableCapabilities, "service.status")
		if helper != nil && helper.ProbeService(ctx) == nil {
			availableCapabilities = append(availableCapabilities, "service.start", "service.stop", "service.restart")
			availableCapabilities = append(availableCapabilities, managementcap.Detect(ctx, cfg.FRP.ServiceName, cfg.FRP.ConfigPath, cfg.FRP.BinaryPath)...)
		}
	}
	if runtime.GOOS == "linux" && helper != nil && helper.Probe(ctx) == nil {
		availableCapabilities = append(availableCapabilities, "risk.repair.config_permissions")
		if cfg.Role == "server" && strings.EqualFold(filepath.Ext(cfg.FRP.ConfigPath), ".toml") {
			availableCapabilities = append(availableCapabilities, "risk.repair.admin_loopback")
		}
	} else if runtime.GOOS == "darwin" && remediator.CanRepairPermissions(ctx) {
		availableCapabilities = append(availableCapabilities, "risk.repair.config_permissions")
	}
	client.WithCapabilities(availableCapabilities...)
	for {
		if err := client.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Error("agent channel stopped", "error", err)
			time.Sleep(time.Second)
			continue
		}
		return
	}
}

func baseCapabilities() []string {
	return []string{"inspect", "runtime.collect", "certificate.rotate", "risk.scan"}
}

func fatal(err error) { slog.Error("fatal", "error", err); os.Exit(1) }
