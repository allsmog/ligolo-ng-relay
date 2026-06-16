// Ligolo-ng
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseTokenTTLSeconds(t *testing.T) {
	seconds, err := parseTokenTTLSeconds("30m")
	if err != nil {
		t.Fatalf("parse token TTL: %v", err)
	}
	if seconds != 1800 {
		t.Fatalf("seconds = %d, want 1800", seconds)
	}
}

func TestParseTokenTTLSecondsRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"", "0s", "-1m", "forever"} {
		if _, err := parseTokenTTLSeconds(value); err == nil {
			t.Fatalf("parse token TTL %q succeeded, want error", value)
		}
	}
}

func TestRunOpsFailsOnWarning(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/relay/ops" {
			t.Fatalf("path = %q, want /api/v1/relay/ops", r.URL.Path)
		}
		if got := r.URL.Query().Get("with_ipv6"); got != "true" {
			t.Fatalf("with_ipv6 = %q, want true", got)
		}
		if got := r.URL.Query().Get("interface_prefix"); got != "relaytest" {
			t.Fatalf("interface_prefix = %q, want relaytest", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"warning","summary":{"warnings":1}}`))
	}))
	defer server.Close()

	c := &client{
		baseURL:    server.URL,
		token:      "test-token",
		httpClient: server.Client(),
	}
	err := runOps(c, []string{"--with-ipv6", "--interface-prefix", "relaytest", "--fail-on-warning"})
	if err == nil {
		t.Fatal("runOps succeeded, want warning error")
	}
	if !strings.Contains(err.Error(), `relay ops status is "warning"`) {
		t.Fatalf("runOps error = %v", err)
	}
}

func TestRunChainPlanQueriesPlanEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/chain_route_plan" {
			t.Fatalf("path = %q, want /api/v1/chain_route_plan", r.URL.Path)
		}
		if got := r.URL.Query().Get("with_ipv6"); got != "true" {
			t.Fatalf("with_ipv6 = %q, want true", got)
		}
		if got := r.URL.Query().Get("interface_prefix"); got != "relaytest" {
			t.Fatalf("interface_prefix = %q, want relaytest", got)
		}
		if got := r.URL.Query().Get("start"); got != "true" {
			t.Fatalf("start = %q, want true", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","summary":{"apply":1},"decisions":[]}`))
	}))
	defer server.Close()

	c := &client{
		baseURL:    server.URL,
		token:      "test-token",
		httpClient: server.Client(),
	}
	if err := runChainPlan(c, []string{"--with-ipv6", "--interface-prefix", "relaytest", "--start"}); err != nil {
		t.Fatalf("runChainPlan: %v", err)
	}
}

func TestRunChainRepairQueriesPlanEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/chain_repair_plan" {
			t.Fatalf("path = %q, want /api/v1/chain_repair_plan", r.URL.Path)
		}
		if got := r.URL.Query().Get("with_ipv6"); got != "true" {
			t.Fatalf("with_ipv6 = %q, want true", got)
		}
		if got := r.URL.Query().Get("interface_prefix"); got != "relaytest" {
			t.Fatalf("interface_prefix = %q, want relaytest", got)
		}
		if got := r.URL.Query().Get("start"); got != "true" {
			t.Fatalf("start = %q, want true", got)
		}
		if got := r.URL.Query().Get("prune_conflicts"); got != "true" {
			t.Fatalf("prune_conflicts = %q, want true", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"warning","summary":{"actions":1},"actions":[]}`))
	}))
	defer server.Close()

	c := &client{
		baseURL:    server.URL,
		token:      "test-token",
		httpClient: server.Client(),
	}
	if err := runChainRepair(c, []string{"--with-ipv6", "--interface-prefix", "relaytest", "--start", "--prune-conflicts"}); err != nil {
		t.Fatalf("runChainRepair: %v", err)
	}
}

func TestRunChainRepairApplyPostsRepairRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/chain_repair" {
			t.Fatalf("path = %q, want /api/v1/chain_repair", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %q, want POST", r.Method)
		}
		var req struct {
			WithIPv6        bool
			InterfacePrefix string
			Start           bool
			PruneConflicts  bool
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if !req.WithIPv6 || req.InterfacePrefix != "relaytest" || !req.Start || !req.PruneConflicts {
			t.Fatalf("request = %+v, want all chain repair flags set", req)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"warning","summary":{"applied":1},"actions":[]}`))
	}))
	defer server.Close()

	c := &client{
		baseURL:    server.URL,
		token:      "test-token",
		httpClient: server.Client(),
	}
	if err := runChainRepair(c, []string{"--with-ipv6", "--interface-prefix", "relaytest", "--start", "--prune-conflicts", "--apply"}); err != nil {
		t.Fatalf("runChainRepair apply: %v", err)
	}
}

func TestRunChainFailoverQueriesPlanEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/chain_failover_plan" {
			t.Fatalf("path = %q, want /api/v1/chain_failover_plan", r.URL.Path)
		}
		if got := r.URL.Query().Get("include_commands"); got != "true" {
			t.Fatalf("include_commands = %q, want true", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"warning","summary":{"recommendations":1},"recommendations":[]}`))
	}))
	defer server.Close()

	c := &client{
		baseURL:    server.URL,
		token:      "test-token",
		httpClient: server.Client(),
	}
	if err := runChainFailover(c, []string{"--include-commands"}); err != nil {
		t.Fatalf("runChainFailover: %v", err)
	}
}
