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

// Package transport defines the data-plane abstraction used by the refactored
// Ligolo architecture.
//
// The legacy code hard-wired hashicorp/yamux over a single TLS connection. That
// couples every logical stream to one TCP connection and produces TCP-over-TCP
// meltdown on lossy/high-latency links. This package hides the multiplexer
// behind a small interface so the data plane can run over QUIC (default, no
// cross-stream head-of-line blocking, connection migration) or, when UDP is
// blocked, fall back to TLS+yamux without any change to the rest of the program.
package transport

import (
	"context"
	"net"
)

// Stream is a single reliable, bidirectional, multiplexed byte stream.
//
// It satisfies net.Conn so streams can be handed directly to the existing
// io.Copy-based relay (pkg/relay) and to gVisor's gonet adapters.
type Stream interface {
	net.Conn
}

// Session is an authenticated, multiplexed connection between two nodes.
// Many Streams ride a single Session. Concrete implementations wrap a QUIC
// connection or a TLS+yamux session.
type Session interface {
	// Open creates a new outbound stream. The peer observes it once the first
	// bytes are written.
	Open(ctx context.Context) (Stream, error)
	// Accept blocks until the peer opens a stream.
	Accept(ctx context.Context) (Stream, error)
	// Close tears down the session and every stream on it.
	Close() error
	// IsClosed reports whether the session can no longer be used.
	IsClosed() bool
	RemoteAddr() net.Addr
	LocalAddr() net.Addr
	// Kind identifies the underlying transport implementation.
	Kind() Kind
}

// Listener accepts inbound Sessions (server side).
type Listener interface {
	Accept(ctx context.Context) (Session, error)
	Close() error
	Addr() net.Addr
	Kind() Kind
}

// Dialer establishes an outbound Session (agent side, reverse-connecting).
type Dialer interface {
	Dial(ctx context.Context, addr string) (Session, error)
	Kind() Kind
}

// Kind enumerates the available transport implementations. The agent advertises
// the transports it can use and the server picks the best mutually supported
// one, preferring QUIC.
type Kind uint8

const (
	// KindQUIC is the preferred transport: UDP based, per-stream loss recovery,
	// connection migration and 0-RTT resumption.
	KindQUIC Kind = iota
	// KindTLSMux is the firewall-traversal fallback: TLS 1.3 over TCP with a
	// userland yamux multiplexer.
	KindTLSMux
)

func (k Kind) String() string {
	switch k {
	case KindQUIC:
		return "quic"
	case KindTLSMux:
		return "tls+mux"
	default:
		return "unknown"
	}
}
