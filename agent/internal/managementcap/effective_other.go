//go:build !linux

package managementcap

import (
	"context"
	"errors"
)

func effectiveServiceUID(context.Context, string) (uint32, error) {
	return 0, errors.New("systemd service identity is unavailable")
}
