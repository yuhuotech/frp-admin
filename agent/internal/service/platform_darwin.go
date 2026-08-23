//go:build darwin

package service

func New(serviceName, launchdPlistPath, binaryPath, configPath, role string) *Launchd {
	return NewLaunchd(serviceName, launchdPlistPath, binaryPath, configPath, role)
}
