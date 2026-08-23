//go:build linux

package configmgr

import (
	"path/filepath"

	"golang.org/x/sys/unix"
)

func platformAtomicExchange() bool { return true }

func exchangeFiles(left, right string) (bool, error) {
	if err := unix.Renameat2(unix.AT_FDCWD, left, unix.AT_FDCWD, right, unix.RENAME_EXCHANGE); err != nil {
		return false, err
	}
	if err := syncDir(filepath.Dir(left)); err != nil {
		return true, err
	}
	if filepath.Dir(right) != filepath.Dir(left) {
		if err := syncDir(filepath.Dir(right)); err != nil {
			return true, err
		}
	}
	return true, nil
}
