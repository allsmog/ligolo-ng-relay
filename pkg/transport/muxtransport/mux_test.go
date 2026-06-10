package muxtransport_test

import (
	"context"
	"crypto/tls"
	"io"
	"testing"
	"time"

	"github.com/nicocha30/ligolo-ng/pkg/tlsutils"
	"github.com/nicocha30/ligolo-ng/pkg/transport"
	"github.com/nicocha30/ligolo-ng/pkg/transport/muxtransport"
)

// TestMuxRoundTrip exercises the TLS+yamux fallback end to end: a client dials,
// opens a stream, and the server echoes the payload back. This is the path used
// when QUIC's UDP is blocked, so a broken handshake or stream plumbing here
// silently disables firewall traversal.
func TestMuxRoundTrip(t *testing.T) {
	crt, err := tlsutils.NewSelfCert(nil).GetCertificate("mux-test")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := muxtransport.Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*crt}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		srv, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		st, err := srv.Accept(ctx)
		if err != nil {
			return
		}
		io.Copy(st, st) // echo until the client closes its stream
	}()

	client, err := muxtransport.NewDialer(&tls.Config{InsecureSkipVerify: true}).Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if client.Kind() != transport.KindTLSMux {
		t.Errorf("Kind() = %v, want KindTLSMux", client.Kind())
	}

	st, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := st.Write([]byte("ping-mux")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len("ping-mux"))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping-mux" {
		t.Errorf("got %q, want %q", buf, "ping-mux")
	}
}
