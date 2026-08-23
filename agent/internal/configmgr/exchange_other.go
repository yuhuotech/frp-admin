//go:build !linux

package configmgr

func platformAtomicExchange() bool { return false }

func exchangeFiles(string, string) (bool, error) { return false, nil }
