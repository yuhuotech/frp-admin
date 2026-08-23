package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/app"
	"github.com/frp-admin/frp-admin/server/internal/config"
)

var version = "dev"

func main() {
	path := flag.String("config", "", "path to YAML configuration")
	flag.Parse()
	cfg, e := config.Load(*path)
	if e != nil {
		slog.Error("load configuration", "error", e)
		os.Exit(1)
	}
	level := slog.LevelInfo
	if cfg.Log.Level == "debug" {
		level = slog.LevelDebug
	} else if cfg.Log.Level == "warn" {
		level = slog.LevelWarn
	} else if cfg.Log.Level == "error" {
		level = slog.LevelError
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})).With("service", "frp-admin-server", "version", version)
	a, e := app.New(context.Background(), cfg, logger)
	if e != nil {
		logger.Error("initialize server", "error", e)
		os.Exit(1)
	}
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("server listening", "http_address", cfg.HTTP.Address, "grpc_address", cfg.GRPC.Address, "database_driver", cfg.Database.Driver)
		serverErr <- a.Run()
	}()
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case e = <-serverErr:
		if e != nil {
			logger.Error("server stopped", "error", e)
		}
	case <-sigCtx.Done():
		logger.Info("shutdown requested")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if shutdownErr := a.Shutdown(ctx); shutdownErr != nil {
		logger.Error("shutdown failed", "error", shutdownErr)
		os.Exit(1)
	}
	if e != nil {
		os.Exit(1)
	}
}
