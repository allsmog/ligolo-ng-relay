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

func TestALPNNegotiation(t *testing.T) {
	crt, err := tlsutils.NewSelfCert(nil).GetCertificate("alpn-test")
	if err != nil {
		t.Fatal(err)
	}
	// Server defaults to DefaultALPN ("h3") — no ligolo-specific fingerprint.
	ln, err := quictransport.Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*crt}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			if _, err := ln.Accept(context.Background()); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Matching ALPN (default h3 on both ends) connects.
	if _, err := quictransport.NewDialer(&tls.Config{InsecureSkipVerify: true}).Dial(ctx, ln.Addr().String()); err != nil {
		t.Fatalf("matching ALPN should connect: %v", err)
	}

	// Mismatched ALPN ("h2" vs "h3") must be rejected by the TLS handshake.
	bad := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}
	if _, err := quictransport.NewDialer(bad).Dial(ctx, ln.Addr().String()); err == nil {
		t.Fatal("mismatched ALPN should fail to connect")
	}
}

func TestDefaultALPNIsBenign(t *testing.T) {
	if quictransport.DefaultALPN == "ligolo/2" || quictransport.DefaultALPN == "" {
		t.Fatalf("default ALPN %q is a fingerprint; want a benign value like h3", quictransport.DefaultALPN)
	}
}
