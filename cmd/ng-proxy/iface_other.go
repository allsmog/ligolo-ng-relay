//go:build !linux

package main

// On non-Linux platforms wireguard-go's tun.CreateTUN creates the interface
// itself, so these are no-ops.
func createTUN(name string) error { return nil }
func deleteTUN(name string)       {}
