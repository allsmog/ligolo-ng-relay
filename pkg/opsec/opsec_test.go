package opsec

import (
	"testing"
	"time"
)

func TestRandomProcessName(t *testing.T) {
	for i := 0; i < 100; i++ {
		n := RandomProcessName()
		if n == "" {
			t.Fatal("RandomProcessName returned empty")
		}
		// Must fit the kernel PR_SET_NAME limit or SetProcessName silently truncates.
		if len(n) > 15 {
			t.Fatalf("name %q exceeds 15-byte PR_SET_NAME limit", n)
		}
	}
}

func TestJitterBounds(t *testing.T) {
	base := 10 * time.Second
	if Jitter(base, 0) != base {
		t.Fatal("frac=0 must return base unchanged")
	}
	for i := 0; i < 1000; i++ {
		j := Jitter(base, 0.3)
		if j < 7*time.Second || j > 13*time.Second {
			t.Fatalf("jitter %v out of ±30%% bounds", j)
		}
	}
}
