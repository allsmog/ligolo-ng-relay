//go:build linux

package opsec

import (
	"os"
	"strings"
	"testing"
)

// TestSetProcessName verifies PR_SET_NAME changes /proc/self/comm.
func TestSetProcessName(t *testing.T) {
	SetProcessName("ng-opsec-test")
	b, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Skipf("cannot read /proc/self/comm: %v", err)
	}
	got := strings.TrimSpace(string(b))
	if got != "ng-opsec-test" {
		t.Errorf("comm = %q, want ng-opsec-test", got)
	}

	// Names longer than 15 bytes are truncated by the kernel.
	SetProcessName("a-very-long-process-name-here")
	b, _ = os.ReadFile("/proc/self/comm")
	if got := strings.TrimSpace(string(b)); len(got) > 15 {
		t.Errorf("comm %q exceeds 15 bytes", got)
	}
}
