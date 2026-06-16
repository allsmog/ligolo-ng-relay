// Ligolo-ng
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package app

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/allsmog/ligolo-ng-relay/pkg/controller"
	"github.com/allsmog/ligolo-ng-relay/pkg/protocol"
	"github.com/allsmog/ligolo-ng-relay/pkg/proxy"
	"github.com/hashicorp/yamux"
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

func TestChainRouteInfosReportsDuplicateRouteConflicts(t *testing.T) {
	resetAppTestState(t)

	AgentList[1] = &controller.LigoloAgent{
		Name:      "root@agent-a",
		SessionID: "agent-a",
		Session:   testYamuxSession(t),
		Network: []protocol.NetInterface{
			{Addresses: []string{"10.20.30.5/24"}},
		},
	}
	AgentList[2] = &controller.LigoloAgent{
		Name:      "root@agent-b",
		SessionID: "agent-b",
		Session:   testYamuxSession(t),
		Network: []protocol.NetInterface{
			{Addresses: []string{"10.20.30.8/24"}},
		},
	}

	routes := chainRouteInfos(false, "relaytest")
	if len(routes) != 2 {
		t.Fatalf("routes = %d, want 2: %+v", len(routes), routes)
	}
	for _, route := range routes {
		if !route.Conflict {
			t.Fatalf("route conflict was not flagged: %+v", route)
		}
		if len(route.ConflictWith) != 1 {
			t.Fatalf("route conflict peers = %v, want one peer", route.ConflictWith)
		}
		if route.Warning == "" {
			t.Fatalf("route warning is empty: %+v", route)
		}
	}
}

func TestRelayDoctorReportDeduplicatesWarnings(t *testing.T) {
	resetAppTestState(t)

	AgentList[1] = &controller.LigoloAgent{
		Name:      "root@agent-a",
		SessionID: "agent-a",
		Session:   testYamuxSession(t),
		Network: []protocol.NetInterface{
			{Addresses: []string{"10.20.30.5/24"}},
		},
	}
	AgentList[2] = &controller.LigoloAgent{
		Name:      "root@agent-b",
		SessionID: "agent-b",
		Session:   testYamuxSession(t),
		Network: []protocol.NetInterface{
			{Addresses: []string{"10.20.30.8/24"}},
		},
	}
	AgentList[1].RecordRelayEvent("auth_rejected", "10.0.0.5:4444", "relay auth token rejected")
	cachePathRTT("agent-a", 1)
	cachePathRTT("agent-b", 2)

	report := relayDoctorReport(false, "relaytest")
	if report.Status != "warning" {
		t.Fatalf("doctor status = %q, want warning", report.Status)
	}
	var routeWarningCount int
	var relayWarningFound bool
	for _, warning := range report.Warnings {
		if strings.Contains(warning, "advertised by multiple agents") {
			routeWarningCount++
		}
		if strings.Contains(warning, "relay auth token rejected") {
			relayWarningFound = true
		}
	}
	if routeWarningCount != 1 {
		t.Fatalf("duplicate route warning count = %d, want 1: %v", routeWarningCount, report.Warnings)
	}
	if !relayWarningFound {
		t.Fatalf("relay auth warning not found: %v", report.Warnings)
	}
}

func resetAppTestState(t *testing.T) {
	oldAgentList := AgentList
	oldChainMgr := ChainMgr

	AgentListMutex.Lock()
	AgentList = make(map[int]*controller.LigoloAgent)
	AgentListMutex.Unlock()
	ChainMgr = proxy.NewChainManager()

	pathRTTCache.Lock()
	oldPathRTTEntries := pathRTTCache.entries
	pathRTTCache.entries = make(map[string]pathRTTCacheEntry)
	pathRTTCache.Unlock()

	t.Cleanup(func() {
		AgentListMutex.Lock()
		AgentList = oldAgentList
		AgentListMutex.Unlock()
		ChainMgr = oldChainMgr

		pathRTTCache.Lock()
		pathRTTCache.entries = oldPathRTTEntries
		pathRTTCache.Unlock()
	})
}

func testYamuxSession(t *testing.T) *yamux.Session {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	serverSession, err := yamux.Server(serverConn, yamux.DefaultConfig())
	if err != nil {
		t.Fatalf("yamux server: %v", err)
	}
	clientSession, err := yamux.Client(clientConn, yamux.DefaultConfig())
	if err != nil {
		t.Fatalf("yamux client: %v", err)
	}
	t.Cleanup(func() {
		clientSession.Close()
		serverSession.Close()
		clientConn.Close()
		serverConn.Close()
	})
	return clientSession
}

func cachePathRTT(sessionID string, value int64) {
	pathRTTCache.Lock()
	defer pathRTTCache.Unlock()
	pathRTTCache.entries[sessionID] = pathRTTCacheEntry{
		value:     &value,
		checkedAt: time.Now(),
	}
}
