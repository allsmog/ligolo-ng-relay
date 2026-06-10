package main

import (
	"testing"

	"github.com/nicocha30/ligolo-ng/pkg/wire"
)

// TestAllocName verifies interface-name allocation skips names already in use,
// without creating real TUN devices.
func TestAllocName(t *testing.T) {
	m := newTunnelManager(nil, "ligolo")

	if got := m.allocNameLocked(); got != "ligolo" {
		t.Fatalf("first name = %q, want ligolo", got)
	}

	m.tunnels["a"] = &agentTunnel{ifName: "ligolo"}
	if got := m.allocNameLocked(); got != "ligolo1" {
		t.Fatalf("second name = %q, want ligolo1", got)
	}

	m.tunnels["b"] = &agentTunnel{ifName: "ligolo1"}
	if got := m.allocNameLocked(); got != "ligolo2" {
		t.Fatalf("third name = %q, want ligolo2", got)
	}

	if !m.nameInUseLocked("ligolo") || m.nameInUseLocked("ligolo9") {
		t.Fatal("nameInUseLocked incorrect")
	}
}

// TestAgentSubnets verifies routable networks are derived from agent interfaces,
// skipping loopback and link-local, and de-duplicating.
func TestAgentSubnets(t *testing.T) {
	ifaces := []wire.NetInterface{
		{Name: "lo", Addresses: []string{"127.0.0.1/8", "::1/128"}},
		{Name: "eth0", Addresses: []string{"192.168.1.50/24", "fe80::1/64"}},
		{Name: "eth1", Addresses: []string{"10.10.0.5/16", "192.168.1.99/24"}}, // dup subnet
	}
	got := agentSubnets(ifaces)

	want := map[string]bool{"192.168.1.0/24": true, "10.10.0.0/16": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want keys %v", got, want)
	}
	for _, s := range got {
		if !want[s] {
			t.Errorf("unexpected subnet %q (loopback/link-local/dup should be excluded)", s)
		}
	}
}
