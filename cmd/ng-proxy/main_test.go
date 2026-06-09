package main

import "testing"

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
