// Ligolo-ng
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package node

import (
	"context"
	"net"

	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/adapters/gonet"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/header"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/stack"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/icmp"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/tcp"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/udp"
	"github.com/nicocha30/gvisor-ligolo/pkg/waiter"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netstack"
	"github.com/nicocha30/ligolo-ng/pkg/relay"
	"github.com/nicocha30/ligolo-ng/pkg/session"
	"github.com/nicocha30/ligolo-ng/pkg/wire"
	"github.com/sirupsen/logrus"
)

// magicSubnet is the 240.0.0.0/4 range remapped to the agent's loopback.
var magicSubnet = net.IPNet{IP: net.IPv4(240, 0, 0, 0), Mask: []byte{0xf0, 0x00, 0x00, 0x00}}

// HandlePacket bridges one gVisor userland flow to the agent over the transport
// abstraction. It is the transport-agnostic replacement for the yamux-specific
// netstack.HandlePacket: instead of a *yamux.Session it drives a Server +
// session.Session, so the same data plane works over QUIC or TLS+mux.
func HandlePacket(srv *Server, sess *session.Session, nstack *stack.Stack, localConn netstack.TunConn) {
	ctx := context.Background()

	switch localConn.Protocol {
	case icmp.ProtocolNumber4:
		handleICMP(ctx, srv, sess, nstack, localConn)
		return
	}

	var endpointID stack.TransportEndpointID
	var protoTransport, protoNet uint8
	switch localConn.Protocol {
	case tcp.ProtocolNumber:
		endpointID = localConn.GetTCP().EndpointID
		protoTransport = wire.TransportTCP
	case udp.ProtocolNumber:
		endpointID = localConn.GetUDP().EndpointID
		protoTransport = wire.TransportUDP
	default:
		return
	}

	if endpointID.LocalAddress.To4() != (tcpip.Address{}) {
		protoNet = wire.NetworkV4
	} else {
		protoNet = wire.NetworkV6
	}

	targetIP := endpointID.LocalAddress.String()
	if magicSubnet.Contains(net.ParseIP(targetIP)) {
		targetIP = "127.0.0.1"
	}
	logrus.Debugf("forward flow: %s -> %s:%d (transport=%d)", endpointID.RemoteAddress, targetIP, endpointID.LocalPort, protoTransport)

	req := wire.ConnectRequest{
		Net:       protoNet,
		Transport: protoTransport,
		Address:   targetIP,
		Port:      endpointID.LocalPort,
	}

	// UDP-over-datagram fast path: when negotiated, carry the flow over the
	// transport's datagram channel instead of a reliable stream.
	if localConn.IsUDP() {
		if hub := srv.dgramHubFor(sess.ID); hub != nil {
			handleUDPDatagram(ctx, srv, sess, hub, nstack, localConn, req)
			return
		}
	}

	stream, reset, err := srv.OpenConnect(ctx, sess, req)
	if err != nil {
		if err == ErrConnectFailed {
			localConn.Terminate(reset)
		} else {
			logrus.Debugf("connect to %s:%d failed: %v", targetIP, endpointID.LocalPort, err)
			localConn.Terminate(false)
		}
		return
	}

	var wq waiter.Queue
	if localConn.IsTCP() {
		ep, iperr := localConn.GetTCP().Request.CreateEndpoint(&wq)
		if iperr != nil {
			stream.Close()
			localConn.Terminate(true)
			return
		}
		go relay.StartRelay(stream, gonet.NewTCPConn(&wq, ep))
	} else {
		ep, iperr := localConn.GetUDP().Request.CreateEndpoint(&wq)
		if iperr != nil {
			stream.Close()
			localConn.Terminate(false)
			return
		}
		go relay.StartRelay(stream, gonet.NewUDPConn(nstack, &wq, ep))
	}
}

func handleUDPDatagram(ctx context.Context, srv *Server, sess *session.Session, hub *dgramHub, nstack *stack.Stack, localConn netstack.TunConn, req wire.ConnectRequest) {
	setup, fc, reset, err := srv.OpenDatagramFlow(ctx, sess, hub, req)
	if err != nil {
		if err == ErrConnectFailed {
			localConn.Terminate(reset)
		} else {
			logrus.Debugf("udp datagram flow setup failed: %v", err)
			localConn.Terminate(false)
		}
		return
	}
	var wq waiter.Queue
	ep, iperr := localConn.GetUDP().Request.CreateEndpoint(&wq)
	if iperr != nil {
		setup.Close()
		fc.Close()
		localConn.Terminate(false)
		return
	}
	go bindDatagramFlow(setup, gonet.NewUDPConn(nstack, &wq, ep), fc)
}

func handleICMP(ctx context.Context, srv *Server, sess *session.Session, nstack *stack.Stack, localConn netstack.TunConn) {
	pkt := localConn.GetICMP().Request
	v, ok := pkt.Data().PullUp(header.ICMPv4MinimumSize)
	if !ok {
		return
	}
	h := header.ICMPv4(v)
	if h.Type() != header.ICMPv4Echo {
		return
	}
	iph := header.IPv4(pkt.NetworkHeader().Slice())
	alive, err := srv.HostPing(ctx, sess, iph.DestinationAddress().String())
	if err != nil {
		logrus.Debugf("host ping failed: %v", err)
		return
	}
	if alive {
		netstack.ProcessICMP(nstack, pkt)
	}
}
