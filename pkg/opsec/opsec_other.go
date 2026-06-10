//go:build !linux

package opsec

// setProcessName is a no-op on platforms without a supported mechanism.
func setProcessName(name string) {}
