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

package netstack

import (
	"bytes"
	"errors"

	"encoding/binary"
	"github.com/nicocha30/gvisor-ligolo/pkg/buffer"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/checksum"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/header"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/network/ipv4"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/stack"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/icmp"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/raw"
	"github.com/nicocha30/gvisor-ligolo/pkg/waiter"
	"github.com/sirupsen/logrus"
)

// icmpResponder handle ICMP packets coming to gvisor/netstack.
// Instead of responding to all ICMPs ECHO by default, we try to
// execute a ping on the Agent, and depending of the response, we
// send a ICMP reply back.
func icmpResponder(s *NetStack) error {

	var wq waiter.Queue
	rawProto, rawerr := raw.NewEndpoint(s.stack, ipv4.ProtocolNumber, icmp.ProtocolNumber4, &wq)
	if rawerr != nil {
		return errors.New("could not create raw endpoint")
	}
	if err := rawProto.Bind(tcpip.FullAddress{}); err != nil {
		return errors.New("could not bind raw endpoint")
	}
	go func() {
		we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
		wq.EventRegister(&we)
		for {
			var buff bytes.Buffer
			_, err := rawProto.Read(&buff, tcpip.ReadOptions{})

			if _, ok := err.(*tcpip.ErrWouldBlock); ok {
				// Wait for data to become available.
				select {
				case <-ch:
					_, err := rawProto.Read(&buff, tcpip.ReadOptions{})

					if err != nil {
						if _, ok := err.(*tcpip.ErrWouldBlock); ok {
							// Oh, a race condition?
							continue
						} else {
							// This is bad.
							logrus.Error(err)
							return
						}
					}

					iph := header.IPv4(buff.Bytes())

					hlen := int(iph.HeaderLength())
					if buff.Len() < hlen {
						return
					}

					// Reconstruct a ICMP PacketBuffer from bytes.

					view := buffer.MakeWithData(buff.Bytes())
					packetbuff := stack.NewPacketBuffer(stack.PacketBufferOptions{
						Payload:            view,
						ReserveHeaderBytes: hlen,
					})

					packetbuff.NetworkProtocolNumber = ipv4.ProtocolNumber
					packetbuff.TransportProtocolNumber = icmp.ProtocolNumber4
					packetbuff.NetworkHeader().Consume(hlen)
					tunConn := TunConn{
						Protocol: icmp.ProtocolNumber4,
						Handler:  ICMPConn{Request: packetbuff},
					}

					s.Lock()
					if s.pool == nil || s.pool.Closed() {
						s.Unlock()
						continue // If connPool is closed, ignore packet.
					}

					if err := s.pool.Add(tunConn); err != nil {
						s.Unlock()
						logrus.Error(err)
						continue // Unknown error, continue...
					}
					s.Unlock()
				}
			}

		}
	}()
	return nil
}

// ProcessICMP send back a ICMP echo reply from after receiving a echo request.
// This code come mostly from pkg/tcpip/network/ipv4/icmp.go
func ProcessICMP(nstack *stack.Stack, pkt stack.PacketBufferPtr) {
	// (gvisor) pkg/tcpip/network/ipv4/icmp.go:174 - handleICMP

	// ICMP packets don't have their TransportHeader fields set. See
	// icmp/protocol.go:protocol.Parse for a full explanation.
	v, ok := pkt.Data().PullUp(header.ICMPv4MinimumSize)
	if !ok {
		return
	}
	h := header.ICMPv4(v)
	// Ligolo-ng: not sure why, but checksum is invalid here.
	/*
		// Only do in-stack processing if the checksum is correct.
		if checksum.Checksum(h, pkt.Data().Checksum()) != 0xffff {
			return
		}
	*/
	iph := header.IPv4(pkt.NetworkHeader().Slice())
	var newOptions header.IPv4Options

	// TODO(b/112892170): Meaningfully handle all ICMP types.
	switch h.Type() {
	case header.ICMPv4Echo:
		replyData := stack.PayloadSince(pkt.TransportHeader())
		defer replyData.Release()
		ipHdr := header.IPv4(pkt.NetworkHeader().Slice())

		localAddressBroadcast := pkt.NetworkPacketInfo.LocalAddressBroadcast

		// It's possible that a raw socket expects to receive this.
		pkt = nil

		// Take the base of the incoming request IP header but replace the options.
		replyHeaderLength := uint8(header.IPv4MinimumSize + len(newOptions))
		replyIPHdrView := buffer.NewView(int(replyHeaderLength))
		replyIPHdrView.Write(iph[:header.IPv4MinimumSize])
		replyIPHdrView.Write(newOptions)
		replyIPHdr := header.IPv4(replyIPHdrView.AsSlice())
		replyIPHdr.SetHeaderLength(replyHeaderLength)

		// As per RFC 1122 section 3.2.1.3, when a host sends any datagram, the IP
		// source address MUST be one of its own IP addresses (but not a broadcast
		// or multicast address).
		localAddr := ipHdr.DestinationAddress()
		if localAddressBroadcast || header.IsV4MulticastAddress(localAddr) {
			localAddr = tcpip.Address{}
		}

		r, err := nstack.FindRoute(1, localAddr, ipHdr.SourceAddress(), ipv4.ProtocolNumber, false /* multicastLoop */)
		if err != nil {
			// If we cannot find a route to the destination, silently drop the packet.
			return
		}
		defer r.Release()

		replyIPHdr.SetSourceAddress(r.LocalAddress())
		replyIPHdr.SetDestinationAddress(r.RemoteAddress())
		replyIPHdr.SetTTL(r.DefaultTTL())

		replyICMPHdr := header.ICMPv4(replyData.AsSlice())
		replyICMPHdr.SetType(header.ICMPv4EchoReply)
		replyICMPHdr.SetChecksum(0)
		replyICMPHdr.SetChecksum(^checksum.Checksum(replyData.AsSlice(), 0))

		replyBuf := buffer.MakeWithView(replyIPHdrView)
		replyBuf.Append(replyData.Clone())
		replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(r.MaxHeaderLength()),
			Payload:            replyBuf,
		})

		replyPkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber

		if err := r.WriteHeaderIncludedPacket(replyPkt); err != nil {
			logrus.Error(err)
			return
		}
	}
}

// SendICMPPortUnreachable generates an ICMP Destination Unreachable (Type 3, Code 3)
// packet and injects it back into the TUN interface. This is sent when a UDP connection
// to a remote port is refused (ECONNREFUSED), allowing tools like nmap to detect closed
// UDP ports instantly instead of waiting for a timeout.
//
// Per RFC 792, the ICMP error payload contains the original IP header + first 8 bytes
// of the original datagram (the UDP header), which lets the scanner correlate the
// error with its probe.
func SendICMPPortUnreachable(nstack *stack.Stack, endpointID stack.TransportEndpointID) {
	// The endpointID fields from the perspective of the netstack forwarder:
	//   LocalAddress/LocalPort   = the destination (target host:port)
	//   RemoteAddress/RemotePort = the source (scanner host:port)
	//
	// The ICMP error goes FROM the target back TO the scanner.
	srcAddr := endpointID.LocalAddress
	dstAddr := endpointID.RemoteAddress

	r, err := nstack.FindRoute(1, srcAddr, dstAddr, ipv4.ProtocolNumber, false)
	if err != nil {
		logrus.Debugf("SendICMPPortUnreachable: could not find route: %v", err)
		return
	}
	defer r.Release()

	// Build the "original IP header + first 8 bytes of datagram" payload.
	// This is what goes inside the ICMP error message per RFC 792.
	//
	// Original IP header (20 bytes, no options):
	origIPHdr := make([]byte, header.IPv4MinimumSize)
	ip := header.IPv4(origIPHdr)
	ip.Encode(&header.IPv4Fields{
		TotalLength: header.IPv4MinimumSize + header.UDPMinimumSize,
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     dstAddr, // original packet was FROM scanner
		DstAddr:     srcAddr, // original packet was TO target
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	// First 8 bytes of original datagram = UDP header (src port, dst port, length, checksum)
	origUDPHdr := make([]byte, header.UDPMinimumSize)
	binary.BigEndian.PutUint16(origUDPHdr[0:2], endpointID.RemotePort) // original src port
	binary.BigEndian.PutUint16(origUDPHdr[2:4], endpointID.LocalPort)  // original dst port
	binary.BigEndian.PutUint16(origUDPHdr[4:6], header.UDPMinimumSize) // length
	// checksum left as 0 (optional for UDP in IPv4)

	// Build ICMP Destination Unreachable message:
	// [Type=3][Code=3][Checksum][Unused/0][Original IP Hdr + 8 bytes]
	icmpLen := header.ICMPv4MinimumSize + len(origIPHdr) + len(origUDPHdr)
	icmpHdr := make(header.ICMPv4, icmpLen)
	icmpHdr.SetType(header.ICMPv4DstUnreachable)
	icmpHdr.SetCode(header.ICMPv4PortUnreachable)
	copy(icmpHdr[header.ICMPv4MinimumSize:], origIPHdr)
	copy(icmpHdr[header.ICMPv4MinimumSize+len(origIPHdr):], origUDPHdr)
	icmpHdr.SetChecksum(0)
	icmpHdr.SetChecksum(^checksum.Checksum(icmpHdr, 0))

	// Build outer IP header for the ICMP error packet
	outerIPHdr := make(header.IPv4, header.IPv4MinimumSize)
	outerIPHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + icmpLen),
		TTL:         r.DefaultTTL(),
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     r.LocalAddress(),
		DstAddr:     r.RemoteAddress(),
	})
	outerIPHdr.SetChecksum(^outerIPHdr.CalculateChecksum())

	// Assemble full packet and inject into the network stack
	pktBuf := buffer.MakeWithData(outerIPHdr)
	pktBuf.Append(buffer.NewViewWithData(icmpHdr))
	replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Payload:            pktBuf,
	})
	replyPkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber

	if err := r.WriteHeaderIncludedPacket(replyPkt); err != nil {
		logrus.Debugf("SendICMPPortUnreachable: write error: %v", err)
		return
	}

	logrus.Debugf("Sent ICMP Port Unreachable for %s:%d -> %s:%d",
		dstAddr, endpointID.RemotePort, srcAddr, endpointID.LocalPort)
}
