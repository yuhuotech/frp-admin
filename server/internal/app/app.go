package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
	"github.com/frp-admin/frp-admin/server/internal/agentgateway"
	"github.com/frp-admin/frp-admin/server/internal/alerting"
	"github.com/frp-admin/frp-admin/server/internal/auth"
	"github.com/frp-admin/frp-admin/server/internal/config"
	"github.com/frp-admin/frp-admin/server/internal/configcrypto"
	"github.com/frp-admin/frp-admin/server/internal/configuration"
	"github.com/frp-admin/frp-admin/server/internal/events"
	"github.com/frp-admin/frp-admin/server/internal/httpapi"
	"github.com/frp-admin/frp-admin/server/internal/metrics"
	"github.com/frp-admin/frp-admin/server/internal/node"
	"github.com/frp-admin/frp-admin/server/internal/pki"
	"github.com/frp-admin/frp-admin/server/internal/risk"
	"github.com/frp-admin/frp-admin/server/internal/secretmgr"
	"github.com/frp-admin/frp-admin/server/internal/store/sqlstore"
	"github.com/frp-admin/frp-admin/server/internal/task"
	"github.com/frp-admin/frp-admin/server/internal/upgrade"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type App struct {
	HTTP         *http.Server
	GRPC         *grpc.Server
	Metrics      *http.Server
	grpcAddress  string
	store        *sqlstore.Store
	workerCancel context.CancelFunc
	workerDone   <-chan struct{}
}

func New(ctx context.Context, cfg config.Config, logger *slog.Logger) (*App, error) {
	s, e := sqlstore.Open(ctx, cfg.Database.Driver, cfg.Database.DSN)
	if e != nil {
		return nil, e
	}
	pkiManager, e := pki.LoadOrCreate(cfg.PKI)
	if e != nil {
		s.Close()
		return nil, fmt.Errorf("initialize PKI: %w", e)
	}
	configCipher, e := configcrypto.LoadKeyRing(cfg.MasterKey.File, cfg.MasterKey.CurrentVersion, cfg.MasterKey.KeyFiles)
	if e != nil {
		s.Close()
		return nil, fmt.Errorf("initialize master key: %w", e)
	}
	referencedVersions, e := s.ReferencedKeyVersions(ctx)
	if e != nil {
		s.Close()
		return nil, fmt.Errorf("inspect encrypted data key versions: %w", e)
	}
	for _, version := range referencedVersions {
		if !configCipher.HasKeyVersion(version) {
			s.Close()
			return nil, fmt.Errorf("master key version %q is required by encrypted data but is not configured", version)
		}
	}
	bootstrap := cfg.Bootstrap.Token
	authService := auth.New(s, bootstrap, cfg.Auth.SessionTTL)
	need, e := authService.NeedsBootstrap(ctx)
	if e != nil {
		s.Close()
		return nil, e
	}
	if need && bootstrap == "" {
		s.Close()
		return nil, fmt.Errorf("bootstrap token is required for an empty database; configure FRP_ADMIN_BOOTSTRAP_TOKEN or FRP_ADMIN_BOOTSTRAP_TOKEN_FILE")
	}
	bus := events.New()
	alerter := alerting.New(s, bus, logger, cfg.Alerting.WebhookURL, cfg.Alerting.WebhookSecret, alerting.Options{AllowedHosts: cfg.Alerting.AllowedHosts, AllowPrivateAddresses: cfg.Alerting.AllowPrivateAddresses})
	secretService := secretmgr.New(s, configCipher)
	configService := configuration.New(s, configCipher, bus, secretService)
	configService.SetTaskTimeout(cfg.Tasks.Timeouts.Config)
	gateway := agentgateway.NewService(s, pkiManager, bus, logger, configService)
	gateway.SetAlertSink(alerter)
	configService.SetGateway(gateway)
	taskService := task.New(s, gateway, bus, alerter)
	taskService.SetTimeouts(cfg.Tasks.Timeouts.Inspect, cfg.Tasks.Timeouts.Service)
	upgradeService := upgrade.New(s, gateway, taskService, bus, cfg.Tasks.Timeouts.Upgrade, configCipher)
	riskService := risk.New(s, gateway, taskService, bus, configService)
	gateway.SetUpgradeMaterializer(upgradeService)
	metrics.Default.SetDBStatsProvider(func() metrics.DBStats {
		v := s.DBStats()
		return metrics.DBStats{Open: int64(v.OpenConnections), InUse: int64(v.InUse), Idle: int64(v.Idle), WaitCount: v.WaitCount, WaitDuration: v.WaitDuration}
	})
	workerCtx, workerCancel := context.WithCancel(context.Background())
	var workerWG sync.WaitGroup
	workerWG.Add(2)
	go func() { defer workerWG.Done(); alerter.Run(workerCtx) }()
	go func() { defer workerWG.Done(); taskService.RunReaper(workerCtx, 15*time.Second) }()
	workerDone := make(chan struct{})
	go func() { workerWG.Wait(); close(workerDone) }()
	h := httpapi.New(authService, node.New(s), taskService, upgradeService, configService, secretService, riskService, s, bus, logger, cfg.Auth.SecureCookies, pkiManager.CAPEM(), cfg.Alerting.WebhookURL != "")
	server := &http.Server{Addr: cfg.HTTP.Address, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(pkiManager.TLSConfig())), grpc.UnaryInterceptor(metrics.Default.UnaryServerInterceptor), grpc.StreamInterceptor(metrics.Default.StreamServerInterceptor))
	agentv1.RegisterAgentControlServiceServer(grpcServer, gateway)
	var metricsServer *http.Server
	if cfg.Metrics.Address != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", metrics.Default)
		metricsServer = &http.Server{Addr: cfg.Metrics.Address, Handler: metricsMux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	}
	return &App{HTTP: server, GRPC: grpcServer, Metrics: metricsServer, grpcAddress: cfg.GRPC.Address, store: s, workerCancel: workerCancel, workerDone: workerDone}, nil
}
func (a *App) Run() error {
	httpListener, e := net.Listen("tcp", a.HTTP.Addr)
	if e != nil {
		return fmt.Errorf("listen HTTP: %w", e)
	}
	grpcListener, e := net.Listen("tcp", a.grpcAddress)
	if e != nil {
		httpListener.Close()
		return fmt.Errorf("listen gRPC: %w", e)
	}
	errs := make(chan error, 3)
	go func() {
		e := a.HTTP.Serve(httpListener)
		if e != nil && e != http.ErrServerClosed {
			errs <- fmt.Errorf("serve HTTP: %w", e)
		} else {
			errs <- nil
		}
	}()
	go func() {
		e := a.GRPC.Serve(grpcListener)
		if e != nil {
			errs <- fmt.Errorf("serve gRPC: %w", e)
		} else {
			errs <- nil
		}
	}()
	if a.Metrics != nil {
		go func() {
			e := a.Metrics.ListenAndServe()
			if e != nil && e != http.ErrServerClosed {
				errs <- fmt.Errorf("serve metrics: %w", e)
			} else {
				errs <- nil
			}
		}()
	}
	return <-errs
}
func (a *App) Shutdown(ctx context.Context) error {
	if a.workerCancel != nil {
		a.workerCancel()
	}
	if a.workerDone != nil {
		select {
		case <-a.workerDone:
		case <-ctx.Done():
		}
	}
	e := a.HTTP.Shutdown(ctx)
	if a.Metrics != nil {
		if metricsErr := a.Metrics.Shutdown(ctx); e == nil {
			e = metricsErr
		}
	}
	grpcDone := make(chan struct{})
	go func() { a.GRPC.GracefulStop(); close(grpcDone) }()
	select {
	case <-grpcDone:
	case <-ctx.Done():
		a.GRPC.Stop()
		if e == nil {
			e = ctx.Err()
		}
	}
	dbErr := a.store.Close()
	if e != nil {
		return e
	}
	return dbErr
}
