// Ligolo-ng
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package main

import (
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
