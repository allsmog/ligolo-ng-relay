package wstransport_test

import (
	"context"
	"crypto/tls"
	"io"
	"testing"
	"time"

	"github.com/nicocha30/ligolo-ng/pkg/tlsutils"
	"github.com/nicocha30/ligolo-ng/pkg/transport"
	"github.com/nicocha30/ligolo-ng/pkg/transport/wstransport"
)

// TestWSRoundTrip exercises the WebSocket+yamux fallback end to end over wss.
// This is the last-resort transport selected when both QUIC and raw TLS are
// blocked, so the round trip (TLS upgrade -> websocket -> yamux stream) must
// hold for CDN/web-proxy traversal to work at all.
func TestWSRoundTrip(t *testing.T) {
	crt, err := tlsutils.NewSelfCert(nil).GetCertificate("ws-test")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := wstransport.Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*crt}})
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

	dialer := wstransport.NewDialer(&tls.Config{InsecureSkipVerify: true})
	client, err := dialer.Dial(ctx, "wss://"+ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if client.Kind() != transport.KindWebsocket {
		t.Errorf("Kind() = %v, want KindWebsocket", client.Kind())
	}

	st, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := st.Write([]byte("ping-ws")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len("ping-ws"))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping-ws" {
		t.Errorf("got %q, want %q", buf, "ping-ws")
	}
}
