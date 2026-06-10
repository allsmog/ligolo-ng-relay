package relay

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestStartRelayBidirectional glues two pipe pairs through StartRelay and
// verifies bytes flow in both directions and that closing one end tears the
// relay down (returning from StartRelay). This is the data-plane copy loop
// every tunneled connection rides, so a regression here breaks all forwarding.
func TestStartRelayBidirectional(t *testing.T) {
	c1, c2 := net.Pipe() // src side: c1 is the "client" end
	d1, d2 := net.Pipe() // dst side: d2 is the "backend" end

	done := make(chan error, 1)
	go func() { done <- StartRelay(c2, d1) }()

	// Forward: bytes written at the client end surface at the backend end.
	go func() { c1.Write([]byte("a->b")) }()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(d2, buf); err != nil {
		t.Fatalf("forward read: %v", err)
	}
	if string(buf) != "a->b" {
		t.Errorf("forward: got %q, want %q", buf, "a->b")
	}

	// Reverse: bytes written at the backend end surface at the client end.
	go func() { d2.Write([]byte("b->a")) }()
	buf2 := make([]byte, 4)
	if _, err := io.ReadFull(c1, buf2); err != nil {
		t.Fatalf("reverse read: %v", err)
	}
	if string(buf2) != "b->a" {
		t.Errorf("reverse: got %q, want %q", buf2, "b->a")
	}

	// Closing one end must unblock and return from StartRelay.
	c1.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartRelay did not return after the connection closed")
	}
}
