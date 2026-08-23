package app

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/frp-admin/frp-admin/server/internal/config"
)

func TestEmptyDatabaseRequiresExplicitBootstrapTokenWithoutLoggingCredential(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Database.DSN = filepath.Join(dir, "frp-admin.db")
	cfg.PKI.Directory = filepath.Join(dir, "pki")
	cfg.MasterKey.File = filepath.Join(dir, "master.key")
	var logs bytes.Buffer
	_, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if err == nil || !strings.Contains(err.Error(), "bootstrap token is required") {
		t.Fatalf("expected explicit bootstrap token error, got %v", err)
	}
	if strings.Contains(logs.String(), "bootstrap_token") {
		t.Fatalf("bootstrap credential field reached logs: %s", logs.String())
	}
}
