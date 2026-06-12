// Ligolo-ng
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package app

import (
	"strings"
	"testing"
)

func TestRelayConnectCommandIncludesFingerprintAndToken(t *testing.T) {
	command := relayConnectCommand("0.0.0.0:11602", "ABCD", "relay-secret")

	if !strings.Contains(command, "-accept-fingerprint ABCD") {
		t.Fatalf("connect command missing fingerprint: %s", command)
	}
	if !strings.Contains(command, "-relay-token relay-secret") {
		t.Fatalf("connect command missing relay token: %s", command)
	}
	if !strings.Contains(command, "<relay-agent-reachable-ip>:11602") {
		t.Fatalf("connect command should use reachable placeholder for wildcard bind: %s", command)
	}
}
