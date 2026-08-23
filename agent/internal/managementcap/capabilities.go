package managementcap

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
)

func Detect(ctx context.Context, serviceName, configPath, binaryPath string) []string {
	serviceUID, err := effectiveServiceUID(ctx, serviceName)
	if err != nil {
		return nil
	}
	return detectForUID(uint32(os.Geteuid()), serviceUID, configPath, binaryPath)
}

func detectForUID(agentUID, serviceUID uint32, configPath, binaryPath string) []string {
	if agentUID == 0 || agentUID != serviceUID {
		return nil
	}
	var capabilities []string
	configMutable := safelyMutableBy(configPath, agentUID, false)
	binaryMutable := safelyMutableBy(binaryPath, agentUID, true)
	if configMutable {
		capabilities = append(capabilities, "config.apply", "config.rollback")
	}
	// Upgrade verifies the candidate against the current configuration before
	// replacing the binary, so both managed resources must pass the same
	// ownership and mutability preflight used by the real transaction.
	if configMutable && binaryMutable {
		capabilities = append(capabilities, "frp.upgrade")
	}
	return capabilities
}

func safelyMutableBy(path string, uid uint32, executable bool) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || info.Mode().Perm()&0400 == 0 || executable && info.Mode().Perm()&0100 == 0 {
		return false
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0022 != 0 {
		return false
	}
	parentStat, ok := parent.Sys().(*syscall.Stat_t)
	return ok && parentStat.Uid == uid && parent.Mode().Perm()&0300 == 0300
}
