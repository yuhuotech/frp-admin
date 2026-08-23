//go:build darwin

package managementcap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

func effectiveServiceUID(ctx context.Context, serviceName string) (uint32, error) {
	uid := os.Getuid()
	target := fmt.Sprintf("gui/%d/%s", uid, serviceName)
	if _, err := exec.CommandContext(ctx, "launchctl", "print", target).CombinedOutput(); err != nil {
		return 0, errors.New("launchd service is unavailable")
	}
	return uint32(uid), nil
}
