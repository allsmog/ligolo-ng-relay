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

// Package operator implements the multi-operator control API: a typed RPC
// surface over a mutual-TLS connection that lets several operators share one
// server's agent pool concurrently (the Sliver multiplayer model).
//
// Each operator authenticates with a client certificate; the hub identifies the
// operator by the certificate common name and authorizes every call. The wire
// format reuses the project's length-prefixed framing (msgpack payloads) rather
// than gRPC/protobuf so the build needs no protoc; the message set below is the
// service contract and could be re-expressed as a .proto without changing the
// architecture.
package operator

import (
	"errors"
	"fmt"
	"io"

	"github.com/shamaton/msgpack/v2"
)

// MsgType identifies an operator RPC message.
type MsgType uint8

const (
	// Requests (operator -> hub).
	TypeListAgentsRequest MsgType = iota
	TypeAddListenerRequest
	TypeStopListenerRequest
	TypeKillAgentRequest
	TypeSubscribeRequest

	// Responses (hub -> operator).
	TypeListAgentsResponse
	TypeAddListenerResponse
	TypeStopListenerResponse
	TypeKillAgentResponse
	TypeError

	// Server-pushed events (hub -> operator, after SubscribeRequest).
	TypeAgentEvent
)

const frameHeaderLen = 6

var frameMagic = [2]byte{0x4C, 0x4F} // "LO"

// MaxPayload bounds an operator message payload.
const MaxPayload = 8 * 1024 * 1024

var (
	ErrBadMagic    = errors.New("operator: bad frame magic")
	ErrPayloadSize = errors.New("operator: payload too large")
)

// ---- Message structs ----

type ListAgentsRequest struct{}

// AgentInfo is a snapshot of an agent session for operators.
type AgentInfo struct {
	ID         string
	Name       string
	PeerKeyHex string
	Online     bool
	Caps       uint32
	Interfaces []string
	Listeners  []ListenerInfo
}

type ListenerInfo struct {
	ID      int32
	Network string
	Address string
	To      string
}

type ListAgentsResponse struct {
	Agents []AgentInfo
}

type AddListenerRequest struct {
	AgentID string
	Network string
	Address string // bind on the agent
	To      string // redirect on the server
}

type AddListenerResponse struct {
	ListenerID int32
}

type StopListenerRequest struct {
	AgentID    string
	ListenerID int32
}

type StopListenerResponse struct{}

type KillAgentRequest struct {
	AgentID string
}

type KillAgentResponse struct{}

type SubscribeRequest struct{}

// AgentEvent is pushed to subscribed operators on agent lifecycle transitions.
type AgentEvent struct {
	Kind  string // connect | resume | disconnect
	Agent AgentInfo
}

// ErrorResponse carries an RPC-level error.
type ErrorResponse struct {
	Message string
}

func (e ErrorResponse) Error() string { return e.Message }

// ---- Framed codec ----

// Codec reads/writes operator messages over a connection.
type Codec struct {
	rw      io.ReadWriter
	Type    MsgType
	Payload interface{}
}

func NewCodec(rw io.ReadWriter) *Codec { return &Codec{rw: rw} }

// Encode writes payload as a framed operator message.
func (c *Codec) Encode(payload interface{}) error {
	t, err := typeOf(payload)
	if err != nil {
		return err
	}
	body, err := msgpack.Marshal(payload)
	if err != nil {
		return err
	}
	if len(body) > MaxPayload {
		return ErrPayloadSize
	}
	// Header layout: magic[2] type[1] length[3]-BE.
	var hdr [frameHeaderLen]byte
	hdr[0], hdr[1] = frameMagic[0], frameMagic[1]
	hdr[2] = uint8(t)
	hdr[3] = byte(len(body) >> 16)
	hdr[4] = byte(len(body) >> 8)
	hdr[5] = byte(len(body))
	if _, err := c.rw.Write(hdr[:]); err != nil {
		return err
	}
	_, err = c.rw.Write(body)
	return err
}

// Decode reads the next framed operator message into c.Type / c.Payload.
func (c *Codec) Decode() error {
	var hdr [frameHeaderLen]byte
	if _, err := io.ReadFull(c.rw, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != frameMagic[0] || hdr[1] != frameMagic[1] {
		return ErrBadMagic
	}
	t := MsgType(hdr[2])
	length := int(hdr[3])<<16 | int(hdr[4])<<8 | int(hdr[5])
	if length > MaxPayload {
		return ErrPayloadSize
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(c.rw, body); err != nil {
		return err
	}
	p, err := newOf(t)
	if err != nil {
		return err
	}
	if err := msgpack.Unmarshal(body, p); err != nil {
		return fmt.Errorf("operator: decode type %d: %w", t, err)
	}
	c.Type = t
	c.Payload = p
	return nil
}

func typeOf(payload interface{}) (MsgType, error) {
	switch payload.(type) {
	case ListAgentsRequest, *ListAgentsRequest:
		return TypeListAgentsRequest, nil
	case ListAgentsResponse, *ListAgentsResponse:
		return TypeListAgentsResponse, nil
	case AddListenerRequest, *AddListenerRequest:
		return TypeAddListenerRequest, nil
	case AddListenerResponse, *AddListenerResponse:
		return TypeAddListenerResponse, nil
	case StopListenerRequest, *StopListenerRequest:
		return TypeStopListenerRequest, nil
	case StopListenerResponse, *StopListenerResponse:
		return TypeStopListenerResponse, nil
	case KillAgentRequest, *KillAgentRequest:
		return TypeKillAgentRequest, nil
	case KillAgentResponse, *KillAgentResponse:
		return TypeKillAgentResponse, nil
	case SubscribeRequest, *SubscribeRequest:
		return TypeSubscribeRequest, nil
	case AgentEvent, *AgentEvent:
		return TypeAgentEvent, nil
	case ErrorResponse, *ErrorResponse:
		return TypeError, nil
	default:
		return 0, fmt.Errorf("operator: unknown payload type %T", payload)
	}
}

func newOf(t MsgType) (interface{}, error) {
	switch t {
	case TypeListAgentsRequest:
		return &ListAgentsRequest{}, nil
	case TypeListAgentsResponse:
		return &ListAgentsResponse{}, nil
	case TypeAddListenerRequest:
		return &AddListenerRequest{}, nil
	case TypeAddListenerResponse:
		return &AddListenerResponse{}, nil
	case TypeStopListenerRequest:
		return &StopListenerRequest{}, nil
	case TypeStopListenerResponse:
		return &StopListenerResponse{}, nil
	case TypeKillAgentRequest:
		return &KillAgentRequest{}, nil
	case TypeKillAgentResponse:
		return &KillAgentResponse{}, nil
	case TypeSubscribeRequest:
		return &SubscribeRequest{}, nil
	case TypeAgentEvent:
		return &AgentEvent{}, nil
	case TypeError:
		return &ErrorResponse{}, nil
	default:
		return nil, fmt.Errorf("operator: unknown message type %d", t)
	}
}
