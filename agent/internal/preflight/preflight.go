package preflight

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func SecureStateDir(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("state directory must be absolute")
	}
	if err := rejectUntrustedSymlinkAncestor(path); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory must not be a symlink")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}

func ManagedFile(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("managed path %s is not a regular non-symlink file", path)
	}
	if info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("managed path %s is group/world writable", path)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("managed path %s owner uid %d differs from agent uid %d", path, stat.Uid, os.Geteuid())
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() {
		return nil, fmt.Errorf("managed path parent is unsafe")
	}
	if parent.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("managed path parent is group/world writable")
	}
	return info, nil
}

// Reject links in the portion of the path controlled by the agent user. Root-owned
// platform ancestors such as macOS /var are treated as the trusted boundary.
func rejectUntrustedSymlinkAncestor(path string) error {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			parent := filepath.Dir(current)
			if parent == current {
				return nil
			}
			current = parent
			continue
		}
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != os.Geteuid() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("state directory ancestor %s must not be a symlink", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func DiskSpace(path string, required int64) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return err
	}
	available := int64(stat.Bavail) * int64(stat.Bsize)
	if required < 0 || available < required {
		return fmt.Errorf("available disk bytes %d below required %d", available, required)
	}
	return nil
}

func SameFilesystem(left, right string) error {
	li, err := os.Stat(left)
	if err != nil {
		return err
	}
	ri, err := os.Stat(right)
	if err != nil {
		return err
	}
	ls, lok := li.Sys().(*syscall.Stat_t)
	rs, rok := ri.Sys().(*syscall.Stat_t)
	if lok && rok && ls.Dev != rs.Dev {
		return errors.New("paths are on different filesystems")
	}
	return nil
}
