package configmgr

import (
	"context"
	"errors"
	"os/exec"
)

type CLIVerifier struct{}

func (CLIVerifier) Verify(ctx context.Context, binaryPath, candidatePath string) error {
	err := exec.CommandContext(ctx, binaryPath, "verify", "-c", candidatePath).Run()
	if err != nil {
		return errors.New("frp configuration verification failed")
	}
	return nil
}
