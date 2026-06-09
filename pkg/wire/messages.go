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

package wire

import "fmt"

// MessageType identifies a control message on the wire.
type MessageType uint8

const (
	// Control plane (session lifecycle).
	TypeHelloRequest MessageType = iota
	TypeHelloResponse
	TypeHeartbeatRequest
	TypeHeartbeatResponse
	TypeResumeRequest
	TypeResumeResponse
	TypeAgentKillRequest

	// Data plane (per-stream, opened by the server toward the agent).
	TypeConnectRequest
	TypeConnectResponse
	TypeHostPingRequest
	TypeHostPingResponse

	// Reverse listeners (opened by the agent on the agent's network).
	TypeListenerRequest
	TypeListenerResponse
	TypeListenerBindResponse
	TypeListenerSockRequest
	TypeListenerSockResponse
	TypeListenerSocketReady
	TypeListenerCloseRequest
	TypeListenerCloseResponse
)

// Transport / network selectors reused by ConnectRequest.
const (
	TransportTCP uint8 = iota
	TransportUDP
)

const (
	NetworkV4 uint8 = iota
	NetworkV6
)

// Capability is a feature flag exchanged during the Hello handshake. The server
// and agent each advertise their supported features and operate on the
// intersection, so the two binaries can evolve independently.
type Capability uint32

const (
	CapTCP Capability = 1 << iota
	CapUDP
	CapICMP
	CapReverseListener
	CapResume
	CapHeartbeat
	CapDatagramUDP // carry UDP over QUIC datagrams instead of a stream
)

// Negotiate returns the intersection of two capability sets.
func Negotiate(a, b uint32) uint32 { return a & b }

// Has reports whether the capability set includes c.
func Has(caps uint32, c Capability) bool { return caps&uint32(c) != 0 }

// ---- Control-plane messages ----

// HelloRequest is the first control message an agent sends after the Noise
// handshake. It advertises the agent's identity, capabilities and (optionally)
// a resume token to rebind a prior session.
type HelloRequest struct {
	ProtocolVersion uint8
	AgentVersion    string
	Name            string // user@hostname
	SessionID       string // empty for a fresh session
	ResumeToken     string // empty unless resuming
	Capabilities    uint32
	Interfaces      []NetInterface
}

// HelloResponse completes the handshake. The server echoes the negotiated
// capability set and assigns (or confirms) a session ID and resume token.
type HelloResponse struct {
	ProtocolVersion   uint8
	ServerVersion     string
	AcceptedCaps      uint32
	SessionID         string
	ResumeToken       string
	Resumed           bool
	Err               bool
	ErrString         string
	HeartbeatInterval int // seconds; 0 disables
}

// HeartbeatRequest/Response is an explicit application-level liveness probe.
// Unlike the transport keepalive it does not tear down the session on a single
// miss; the server applies a separate liveness timeout.
type HeartbeatRequest struct {
	Nonce uint64
}

type HeartbeatResponse struct {
	Nonce uint64
}

// ResumeRequest asks the server to rebind an existing session to a new
// transport connection (e.g. after the agent's IP changed).
type ResumeRequest struct {
	SessionID   string
	ResumeToken string
}

type ResumeResponse struct {
	Ok        bool
	ErrString string
}

// AgentKillRequest asks the agent to terminate.
type AgentKillRequest struct{}

// ---- Data-plane messages ----

// ConnectRequest asks the agent to dial a target on its network. The server
// opens one stream per flow and prefixes it with this message.
//
// When Datagram is set (UDP only, negotiated via CapDatagramUDP), the flow is
// carried over the transport's unreliable datagram channel keyed by FlowID
// instead of this stream; the stream is used only to set up and tear down the
// flow.
type ConnectRequest struct {
	Net       uint8
	Transport uint8
	Address   string
	Port      uint16
	Datagram  bool
	FlowID    uint32
}

// ConnectResponse reports whether the dial succeeded. Reset asks the userland
// stack to emit a TCP RST (so nmap sees a closed rather than filtered port).
type ConnectResponse struct {
	Established bool
	Reset       bool
}

// HostPingRequest/Response implement the ICMP liveness check.
type HostPingRequest struct {
	Address string
}

type HostPingResponse struct {
	Alive bool
}

// ---- Reverse-listener messages ----

type ListenerRequest struct {
	Network string
	Address string
}

type ListenerResponse struct {
	ListenerID int32
	Err        bool
	ErrString  string
}

// ListenerBindResponse announces a new inbound connection on a reverse listener.
type ListenerBindResponse struct {
	SockID    int32
	Err       bool
	ErrString string
}

type ListenerSockRequest struct {
	SockID int32
}

type ListenerSockResponse struct {
	Err       bool
	ErrString string
}

// ListenerSocketReady acknowledges that the server end is ready to relay.
type ListenerSocketReady struct {
	Err bool
}

type ListenerCloseRequest struct {
	ListenerID int32
}

type ListenerCloseResponse struct {
	Err       bool
	ErrString string
}

// NetInterface mirrors a network interface for the Hello message.
type NetInterface struct {
	Index        int
	MTU          int
	Name         string
	HardwareAddr string
	Flags        uint
	Addresses    []string
}

// typeOf maps a payload value to its MessageType for encoding.
func typeOf(payload interface{}) (MessageType, error) {
	switch payload.(type) {
	case HelloRequest, *HelloRequest:
		return TypeHelloRequest, nil
	case HelloResponse, *HelloResponse:
		return TypeHelloResponse, nil
	case HeartbeatRequest, *HeartbeatRequest:
		return TypeHeartbeatRequest, nil
	case HeartbeatResponse, *HeartbeatResponse:
		return TypeHeartbeatResponse, nil
	case ResumeRequest, *ResumeRequest:
		return TypeResumeRequest, nil
	case ResumeResponse, *ResumeResponse:
		return TypeResumeResponse, nil
	case AgentKillRequest, *AgentKillRequest:
		return TypeAgentKillRequest, nil
	case ConnectRequest, *ConnectRequest:
		return TypeConnectRequest, nil
	case ConnectResponse, *ConnectResponse:
		return TypeConnectResponse, nil
	case HostPingRequest, *HostPingRequest:
		return TypeHostPingRequest, nil
	case HostPingResponse, *HostPingResponse:
		return TypeHostPingResponse, nil
	case ListenerRequest, *ListenerRequest:
		return TypeListenerRequest, nil
	case ListenerResponse, *ListenerResponse:
		return TypeListenerResponse, nil
	case ListenerBindResponse, *ListenerBindResponse:
		return TypeListenerBindResponse, nil
	case ListenerSockRequest, *ListenerSockRequest:
		return TypeListenerSockRequest, nil
	case ListenerSockResponse, *ListenerSockResponse:
		return TypeListenerSockResponse, nil
	case ListenerSocketReady, *ListenerSocketReady:
		return TypeListenerSocketReady, nil
	case ListenerCloseRequest, *ListenerCloseRequest:
		return TypeListenerCloseRequest, nil
	case ListenerCloseResponse, *ListenerCloseResponse:
		return TypeListenerCloseResponse, nil
	default:
		return 0, fmt.Errorf("wire: unknown payload type %T", payload)
	}
}

// newOf returns a pointer to a fresh message struct for the given type.
func newOf(t MessageType) (interface{}, error) {
	switch t {
	case TypeHelloRequest:
		return &HelloRequest{}, nil
	case TypeHelloResponse:
		return &HelloResponse{}, nil
	case TypeHeartbeatRequest:
		return &HeartbeatRequest{}, nil
	case TypeHeartbeatResponse:
		return &HeartbeatResponse{}, nil
	case TypeResumeRequest:
		return &ResumeRequest{}, nil
	case TypeResumeResponse:
		return &ResumeResponse{}, nil
	case TypeAgentKillRequest:
		return &AgentKillRequest{}, nil
	case TypeConnectRequest:
		return &ConnectRequest{}, nil
	case TypeConnectResponse:
		return &ConnectResponse{}, nil
	case TypeHostPingRequest:
		return &HostPingRequest{}, nil
	case TypeHostPingResponse:
		return &HostPingResponse{}, nil
	case TypeListenerRequest:
		return &ListenerRequest{}, nil
	case TypeListenerResponse:
		return &ListenerResponse{}, nil
	case TypeListenerBindResponse:
		return &ListenerBindResponse{}, nil
	case TypeListenerSockRequest:
		return &ListenerSockRequest{}, nil
	case TypeListenerSockResponse:
		return &ListenerSockResponse{}, nil
	case TypeListenerSocketReady:
		return &ListenerSocketReady{}, nil
	case TypeListenerCloseRequest:
		return &ListenerCloseRequest{}, nil
	case TypeListenerCloseResponse:
		return &ListenerCloseResponse{}, nil
	default:
		return nil, fmt.Errorf("wire: unknown message type %d", t)
	}
}
