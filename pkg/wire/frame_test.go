package wire

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []interface{}{
		HelloRequest{ProtocolVersion: ProtocolVersion, Name: "user@host", Capabilities: uint32(CapTCP | CapUDP)},
		HelloResponse{ProtocolVersion: ProtocolVersion, SessionID: "abcd", AcceptedCaps: uint32(CapTCP), HeartbeatInterval: 30},
		ConnectRequest{Net: NetworkV4, Transport: TransportTCP, Address: "10.0.0.1", Port: 443},
		ConnectResponse{Established: true},
		HeartbeatRequest{Nonce: 12345},
		ListenerBindResponse{SockID: 7},
	}
	for _, in := range cases {
		var buf bytes.Buffer
		if err := NewEncoder(&buf).Encode(in); err != nil {
			t.Fatalf("encode %T: %v", in, err)
		}
		dec := NewDecoder(&buf)
		if err := dec.Decode(); err != nil {
			t.Fatalf("decode %T: %v", in, err)
		}
		if dec.Version != ProtocolVersion {
			t.Errorf("version = %d, want %d", dec.Version, ProtocolVersion)
		}
		if dec.Payload == nil {
			t.Fatalf("nil payload for %T", in)
		}
	}
}

func TestDecodeRejectsBadMagic(t *testing.T) {
	buf := bytes.NewReader([]byte{0x00, 0x00, 2, 0, 0, 0, 0, 0})
	if err := NewDecoder(buf).Decode(); err != ErrBadMagic {
		t.Fatalf("got %v, want ErrBadMagic", err)
	}
}

func TestConnectValuesPreserved(t *testing.T) {
	var buf bytes.Buffer
	in := ConnectRequest{Net: NetworkV6, Transport: TransportUDP, Address: "::1", Port: 53}
	if err := NewEncoder(&buf).Encode(in); err != nil {
		t.Fatal(err)
	}
	dec := NewDecoder(&buf)
	if err := dec.Decode(); err != nil {
		t.Fatal(err)
	}
	got, ok := dec.Payload.(*ConnectRequest)
	if !ok {
		t.Fatalf("payload type = %T", dec.Payload)
	}
	if got.Address != "::1" || got.Port != 53 || got.Net != NetworkV6 || got.Transport != TransportUDP {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestNegotiate(t *testing.T) {
	a := uint32(CapTCP | CapUDP | CapICMP)
	b := uint32(CapTCP | CapResume)
	got := Negotiate(a, b)
	if !Has(got, CapTCP) {
		t.Error("CapTCP should be negotiated")
	}
	if Has(got, CapUDP) || Has(got, CapICMP) || Has(got, CapResume) {
		t.Errorf("unexpected capability in %#x", got)
	}
}
