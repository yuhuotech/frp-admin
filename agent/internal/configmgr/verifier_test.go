package configmgr

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIVerifierDoesNotReturnCommandOutput(t *testing.T) {
	secret := "token=top-secret"
	binary := filepath.Join(t.TempDir(), "frpc")
	script := "#!/bin/sh\nprintf '%s\\n' '" + secret + "' >&2\nexit 1\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	err := (CLIVerifier{}).Verify(context.Background(), binary, filepath.Join(t.TempDir(), "candidate.toml"))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe verifier error=%v", err)
	}
}
