package opsec

import (
	"testing"
	"time"
)

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
