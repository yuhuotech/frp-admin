//go:build linux

package service

func New(serviceName, launchdPlistPath, binaryPath, configPath, role string) *Systemd {
	return NewSystemd(serviceName, binaryPath, configPath, role)
}
