// Ligolo-ng
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package main

import "testing"

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
