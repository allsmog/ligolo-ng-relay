package node

// Userspace verification of the forward data path: a crafted TCP SYN injected
// into the real ligolo gVisor stack (via a channel endpoint instead of a TUN)
// must drive the forwarder -> pool -> HandlePacket -> OpenConnect chain so the
// agent dials the target. This exercises the exact path that a real TUN would,
// but without the TUN device / privileged syscalls a sandbox blocks.

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/nicocha30/gvisor-ligolo/pkg/buffer"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/checksum"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/header"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/link/channel"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/network/ipv4"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/stack"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/tcp"
	"github.com/nicocha30/ligolo-ng/pkg/auth"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netstack"
	"github.com/nicocha30/ligolo-ng/pkg/session"
	"github.com/nicocha30/ligolo-ng/pkg/transport/quictransport"
)

func craftSYN(srcIP, dstIP string, srcPort, dstPort uint16) stack.PacketBufferPtr {
	const ipLen = header.IPv4MinimumSize
	const tcpLen = header.TCPMinimumSize
	buf := make([]byte, ipLen+tcpLen)

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(ipLen + tcpLen),
		TTL:         64,
		Protocol:    uint8(tcp.ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4Slice(net.ParseIP(srcIP).To4()),
		DstAddr:     tcpip.AddrFrom4Slice(net.ParseIP(dstIP).To4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	th := header.TCP(buf[ipLen:])
	th.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     1,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(tcp.ProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(tcpLen))
	th.SetChecksum(^checksum.Checksum(buf[ipLen:], xsum))

	return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf)})
}

func TestForwardPathViaChannel(t *testing.T) {
	if raceEnabled {
		// gVisor's heavily-locked netstack stalls injected-packet delivery under
		// the Go race detector (gVisor itself is not run under -race). This test
		// exercises gVisor's forward path, not our concurrency, so skip it under
		// -race; the rest of the package still runs with -race.
		t.Skip("gVisor netstack packet delivery is unreliable under -race")
	}
	serverID, _ := auth.GenerateIdentity()
	agentID, _ := auth.GenerateIdentity()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Target the tunnel will reach: a TCP listener that signals on accept. The
	// magic IP 240.0.0.0/4 remaps to the agent's 127.0.0.1, so the agent dials
	// here.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case accepted <- struct{}{}:
			default:
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	echoPort, _ := strconv.Atoi(portStr)

	// Real server + agent over QUIC.
	qln, err := quictransport.Listen("127.0.0.1:0", selfCert(t))
	if err != nil {
		t.Fatal(err)
	}
	defer qln.Close()
	gotSession := make(chan *session.Session, 1)
	srv := NewServer(ServerConfig{
		Identity:          serverID,
		HeartbeatInterval: time.Second,
		OnConnect:         func(s *session.Session) { gotSession <- s },
	})
	go srv.Serve(ctx, qln)
	agent := NewAgent(AgentConfig{Identity: agentID, ServerKey: serverID.Public(), ServerAddr: qln.Addr().String()})
	go agent.Serve(ctx, quictransport.NewDialer(&tls.Config{InsecureSkipVerify: true}))

	var sess *session.Session
	select {
	case sess = <-gotSession:
	case <-ctx.Done():
		t.Fatal("agent never connected")
	}

	// Build the real ligolo gVisor stack on a channel endpoint (no TUN).
	ep := channel.New(16, 1500, "")
	pool := netstack.NewConnPool(64)
	ns, err := netstack.NewStackWithEndpoint(netstack.StackSettings{MaxInflight: 1024}, &pool, ep)
	if err != nil {
		t.Fatalf("build stack: %v", err)
	}
	defer ns.Close()

	// Pump intercepted flows into the forward handler, exactly like the proxy.
	go func() {
		for {
			tc, err := pool.Get()
			if err != nil {
				return
			}
			go HandlePacket(srv, sess, ns.GetStack(), tc)
		}
	}()

	// Inject SYNs to a magic IP; HandlePacket remaps it to the agent's
	// 127.0.0.1:echoPort and the agent dials our target. We resend like a real
	// client retransmitting a SYN so the test is robust to scheduling.
	inject := func() {
		pkt := craftSYN("10.1.1.1", "240.0.0.5", 40000, uint16(echoPort))
		ep.InjectInbound(ipv4.ProtocolNumber, pkt)
		pkt.DecRef()
	}
	inject()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-accepted:
			return // forward path drove the agent to dial the target
		case <-ctx.Done():
			t.Fatal("forward flow never reached the target (forwarder->pool->HandlePacket->agent)")
		case <-ticker.C:
			inject()
		}
	}
}
