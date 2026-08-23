//go:build linux

package managementcap

import (
	"context"
	"errors"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

func effectiveServiceUID(ctx context.Context, serviceName string) (uint32, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "show", serviceName, "--property=User,DynamicUser", "--no-pager").Output()
	if err != nil || strings.Contains(string(out), "DynamicUser=yes") {
		return 0, errors.New("systemd service identity is unavailable")
	}
	name := "root"
	for _, line := range strings.Split(string(out), "\n") {
		if value, ok := strings.CutPrefix(line, "User="); ok && value != "" {
			name = value
		}
	}
	if value, err := strconv.ParseUint(name, 10, 32); err == nil {
		return uint32(value), nil
	}
	account, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(account.Uid, 10, 32)
	return uint32(value), err
}
