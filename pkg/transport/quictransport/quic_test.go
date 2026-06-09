package quictransport_test

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/nicocha30/ligolo-ng/pkg/tlsutils"
	"github.com/nicocha30/ligolo-ng/pkg/transport"
	"github.com/nicocha30/ligolo-ng/pkg/transport/quictransport"
)

func TestQUICDatagrams(t *testing.T) {
	crt, err := tlsutils.NewSelfCert(nil).GetCertificate("dg-test")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := quictransport.Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*crt}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srvCh := make(chan transport.Session, 1)
	go func() {
		s, err := ln.Accept(ctx)
		if err == nil {
			srvCh <- s
		}
	}()

	client, err := quictransport.NewDialer(&tls.Config{InsecureSkipVerify: true}).Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	srv := <-srvCh

	// Both ends must expose the datagram capability.
	cd, ok := client.(transport.DatagramSession)
	if !ok {
		t.Fatal("client QUIC session does not implement DatagramSession")
	}
	sd, ok := srv.(transport.DatagramSession)
	if !ok {
		t.Fatal("server QUIC session does not implement DatagramSession")
	}

	// A stream must exist before datagrams flow (handshake completion); open one.
	if _, err := client.Open(ctx); err != nil {
		t.Fatalf("open stream: %v", err)
	}

	if err := cd.SendDatagram([]byte("ping-dgram")); err != nil {
		t.Fatalf("send datagram: %v", err)
	}
	got, err := sd.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatalf("receive datagram: %v", err)
	}
	if string(got) != "ping-dgram" {
		t.Errorf("got %q, want %q", got, "ping-dgram")
	}
}
