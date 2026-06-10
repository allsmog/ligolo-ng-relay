//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// createTUN creates a persistent TUN interface with the same flags gVisor uses
// to open it (IFF_TUN | IFF_NO_PI, single queue), then brings it up. On Linux
// the gVisor link endpoint opens an existing device by name — it does not create
// one — so the proxy must create it first. Using the identical ioctl path (plus
// TUNSETPERSIST) guarantees the device and its single queue match what gVisor
// reopens; a netlink-created Tuntap does not reliably deliver packets to it.
func createTUN(name string) error {
	if _, err := netlink.LinkByName(name); err == nil {
		return setUp(name) // already exists; ensure it's up
	}

	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /dev/net/tun: %w", err)
	}
	defer unix.Close(fd)

	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:unix.IFNAMSIZ-1], name)
	binary.LittleEndian.PutUint16(ifr[unix.IFNAMSIZ:], uint16(unix.IFF_TUN|unix.IFF_NO_PI))
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return fmt.Errorf("TUNSETIFF %s: %w", name, e)
	}
	// Persist the device so it survives this fd closing; gVisor reopens it.
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETPERSIST, 1); e != 0 {
		return fmt.Errorf("TUNSETPERSIST %s: %w", name, e)
	}
	return setUp(name)
}

func setUp(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

// deleteTUN removes a TUN interface created by createTUN.
func deleteTUN(name string) {
	if link, err := netlink.LinkByName(name); err == nil {
		_ = netlink.LinkDel(link)
	}
}
