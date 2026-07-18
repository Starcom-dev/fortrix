//go:build !windows

package main

import "errors"

// maybeRunAsService is a no-op on non-Windows platforms.
func maybeRunAsService() bool { return false }

func installService() error {
	return errors.New("service install is only supported on Windows")
}

func uninstallService() error {
	return errors.New("service uninstall is only supported on Windows")
}
