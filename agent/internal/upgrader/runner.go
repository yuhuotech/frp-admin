package upgrader

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type BinaryRunner interface {
	Version(context.Context, string) (string, error)
	Verify(context.Context, string, string) error
}

type CLIRunner struct{}

func (CLIRunner) Version(ctx context.Context, binary string) (string, error) {
	out, err := exec.CommandContext(ctx, binary, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("version check failed")
	}
	return strings.TrimSpace(string(out)), nil
}

func (CLIRunner) Verify(ctx context.Context, binary, config string) error {
	err := exec.CommandContext(ctx, binary, "verify", "-c", config).Run()
	if err != nil {
		return fmt.Errorf("upgrade candidate configuration verification failed")
	}
	return nil
}
