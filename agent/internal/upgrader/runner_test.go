package upgrader

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIRunnerVerifyDoesNotReturnCommandOutput(t *testing.T) {
	secret := "token=top-secret"
	binary := filepath.Join(t.TempDir(), "frpc")
	script := "#!/bin/sh\nprintf '%s\\n' '" + secret + "' >&2\nexit 1\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	err := (CLIRunner{}).Verify(context.Background(), binary, filepath.Join(t.TempDir(), "current.toml"))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe upgrade verifier error=%v", err)
	}
}
