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

// Package node implements the agent and server of the refactored architecture,
// wiring together the transport, auth, wire and session packages.
package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nicocha30/ligolo-ng/pkg/agent/neterror"
	"github.com/nicocha30/ligolo-ng/pkg/agent/smartping"
	"github.com/nicocha30/ligolo-ng/pkg/auth"
	"github.com/nicocha30/ligolo-ng/pkg/relay"
	"github.com/nicocha30/ligolo-ng/pkg/transport"
	"github.com/nicocha30/ligolo-ng/pkg/wire"
	"github.com/sirupsen/logrus"
)

// AgentConfig configures an Agent.
type AgentConfig struct {
	Identity   auth.Identity // the agent's static keypair
	ServerKey  []byte        // pinned server static public key (32 bytes)
	PSK        []byte        // optional pre-shared key (IKpsk2)
	Version    string
	ServerAddr string
}

// Agent is a reverse-connecting Ligolo agent. All per-connection state lives on
// this value rather than in package globals.
type Agent struct {
	cfg AgentConfig

	// session id / resume token issued by the server, used to reconnect.
	sessionID   atomic.Value // string
	resumeToken atomic.Value // string

	connTrack sync.Map // int32 -> net.Conn (reverse-listener inbound sockets)
	lisSeq    atomic.Int32
	connSeq   atomic.Int32
}

// NewAgent builds an Agent.
func NewAgent(cfg AgentConfig) *Agent {
	a := &Agent{cfg: cfg}
	a.sessionID.Store("")
	a.resumeToken.Store("")
	return a
}

func (a *Agent) caps() uint32 {
	return uint32(wire.CapTCP | wire.CapUDP | wire.CapICMP |
		wire.CapReverseListener | wire.CapResume | wire.CapHeartbeat)
}

// Serve dials the server using the given dialer and runs the agent until ctx is
// cancelled. It does not implement reconnection; the caller drives the retry
// loop (see cmd/ng-agent).
func (a *Agent) Serve(ctx context.Context, dialer transport.Dialer) error {
	sess, err := dialer.Dial(ctx, a.cfg.ServerAddr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer sess.Close()

	logrus.Infof("connected to %s over %s", sess.RemoteAddr(), sess.Kind())

	// 1. Open the control stream and run the Noise handshake (initiator).
	ctrlStream, err := sess.Open(ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	secure, err := auth.HandshakeInitiator(ctrlStream, a.cfg.Identity, a.cfg.ServerKey, a.cfg.PSK)
	if err != nil {
		return fmt.Errorf("noise handshake: %w", err)
	}
	ctrl := wire.NewCodec(secure)

	// 2. Hello / capability negotiation.
	if err := ctrl.Encode(a.buildHello()); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}
	if err := ctrl.Decode(); err != nil {
		return fmt.Errorf("recv hello response: %w", err)
	}
	hr, ok := ctrl.Payload.(*wire.HelloResponse)
	if !ok {
		return errors.New("unexpected control response to hello")
	}
	if hr.Err {
		return fmt.Errorf("server rejected hello: %s", hr.ErrString)
	}
	a.sessionID.Store(hr.SessionID)
	a.resumeToken.Store(hr.ResumeToken)
	logrus.Infof("session established id=%s caps=%#x", hr.SessionID, hr.AcceptedCaps)

	// 3. Serve the control stream (heartbeat / kill) in the background.
	ctrlErr := make(chan error, 1)
	go func() { ctrlErr <- a.serveControl(ctx, ctrl) }()

	// 4. Accept and handle data-plane streams from the server.
	for {
		select {
		case err := <-ctrlErr:
			return err
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		stream, err := sess.Accept(ctx)
		if err != nil {
			return fmt.Errorf("accept stream: %w", err)
		}
		go a.handleStream(stream)
	}
}

func (a *Agent) buildHello() wire.HelloRequest {
	var username, hostname string
	if h, err := os.Hostname(); err == nil {
		hostname = h
	} else {
		hostname = "UNKNOWN"
	}
	if u, err := user.Current(); err == nil {
		username = u.Username
	} else {
		username = "unknown"
	}
	return wire.HelloRequest{
		ProtocolVersion: wire.ProtocolVersion,
		AgentVersion:    a.cfg.Version,
		Name:            fmt.Sprintf("%s@%s", username, hostname),
		SessionID:       a.sessionID.Load().(string),
		ResumeToken:     a.resumeToken.Load().(string),
		Capabilities:    a.caps(),
		Interfaces:      collectInterfaces(),
	}
}

// serveControl handles control-plane messages over the (Noise-encrypted) stream.
func (a *Agent) serveControl(ctx context.Context, ctrl *wire.Codec) error {
	for {
		if err := ctrl.Decode(); err != nil {
			return fmt.Errorf("control stream closed: %w", err)
		}
		switch ctrl.Payload.(type) {
		case *wire.HeartbeatRequest:
			req := ctrl.Payload.(*wire.HeartbeatRequest)
			if err := ctrl.Encode(wire.HeartbeatResponse{Nonce: req.Nonce}); err != nil {
				return err
			}
		case *wire.AgentKillRequest:
			logrus.Info("received kill request, exiting")
			os.Exit(0)
		default:
			logrus.Warnf("unexpected control message %T", ctrl.Payload)
		}
	}
}

// handleStream dispatches a single data-plane stream based on its first frame.
func (a *Agent) handleStream(stream transport.Stream) {
	codec := wire.NewCodec(stream)
	if err := codec.Decode(); err != nil {
		logrus.Debugf("stream decode error: %v", err)
		stream.Close()
		return
	}
	switch msg := codec.Payload.(type) {
	case *wire.ConnectRequest:
		a.handleConnect(stream, codec, msg)
	case *wire.HostPingRequest:
		a.handleHostPing(codec, msg)
	case *wire.ListenerRequest:
		a.handleListener(stream, codec, msg)
	case *wire.ListenerSockRequest:
		a.handleListenerSock(stream, codec, msg)
	case *wire.ListenerCloseRequest:
		a.handleListenerClose(codec, msg)
	default:
		logrus.Warnf("unexpected data-plane message %T", codec.Payload)
		stream.Close()
	}
}

func (a *Agent) handleConnect(stream transport.Stream, codec *wire.Codec, req *wire.ConnectRequest) {
	network := "tcp"
	if req.Transport == wire.TransportUDP {
		network = "udp"
	}
	if req.Net == wire.NetworkV4 {
		network += "4"
	} else {
		network += "6"
	}

	dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var d net.Dialer
	target, err := d.DialContext(dctx, network, fmt.Sprintf("%s:%d", req.Address, req.Port))

	resp := wire.ConnectResponse{}
	if err != nil {
		var serr syscall.Errno
		if errors.As(err, &serr) && neterror.HostResponded(serr) {
			// Tell the userland stack to emit a RST so nmap sees a closed port.
			resp.Reset = true
		}
		resp.Established = false
	} else {
		resp.Established = true
	}
	if encErr := codec.Encode(resp); encErr != nil {
		logrus.Debugf("connect response encode: %v", encErr)
		if target != nil {
			target.Close()
		}
		return
	}
	if resp.Established {
		relay.StartRelay(target, stream)
	}
}

func (a *Agent) handleHostPing(codec *wire.Codec, req *wire.HostPingRequest) {
	_ = codec.Encode(wire.HostPingResponse{Alive: smartping.TryResolve(req.Address)})
}

func (a *Agent) handleListener(stream transport.Stream, codec *wire.Codec, req *wire.ListenerRequest) {
	id := a.lisSeq.Add(1)
	if req.Network == "udp" {
		udpAddr, err := net.ResolveUDPAddr(req.Network, req.Address)
		if err != nil {
			_ = codec.Encode(wire.ListenerResponse{Err: true, ErrString: err.Error()})
			return
		}
		udpConn, err := net.ListenUDP(req.Network, udpAddr)
		if err != nil {
			_ = codec.Encode(wire.ListenerResponse{Err: true, ErrString: err.Error()})
			return
		}
		if err := codec.Encode(wire.ListenerResponse{ListenerID: id}); err != nil {
			udpConn.Close()
			return
		}
		// UDP listeners relay datagrams directly over this stream.
		relay.StartPacketRelay(stream, udpConn)
		udpConn.Close()
		return
	}

	ln, err := net.Listen(req.Network, req.Address)
	if err != nil {
		_ = codec.Encode(wire.ListenerResponse{Err: true, ErrString: err.Error()})
		return
	}
	defer ln.Close()
	if err := codec.Encode(wire.ListenerResponse{ListenerID: id}); err != nil {
		return
	}
	// For each inbound connection, store it under a sock id and announce it. The
	// server then opens a fresh stream with a ListenerSockRequest to drain it.
	for {
		conn, err := ln.Accept()
		if err != nil {
			_ = codec.Encode(wire.ListenerBindResponse{Err: true, ErrString: err.Error()})
			return
		}
		sockID := a.connSeq.Add(1)
		a.connTrack.Store(sockID, conn)
		if err := codec.Encode(wire.ListenerBindResponse{SockID: sockID}); err != nil {
			conn.Close()
			a.connTrack.Delete(sockID)
			return
		}
	}
}

func (a *Agent) handleListenerSock(stream transport.Stream, codec *wire.Codec, req *wire.ListenerSockRequest) {
	v, ok := a.connTrack.LoadAndDelete(req.SockID)
	if !ok {
		_ = codec.Encode(wire.ListenerSockResponse{Err: true, ErrString: "invalid sock id"})
		return
	}
	conn := v.(net.Conn)
	if err := codec.Encode(wire.ListenerSockResponse{}); err != nil {
		conn.Close()
		return
	}
	// Wait for the server's readiness ack before relaying (avoids a race).
	if err := codec.Decode(); err != nil {
		conn.Close()
		return
	}
	ready, ok := codec.Payload.(*wire.ListenerSocketReady)
	if !ok || ready.Err {
		conn.Close()
		return
	}
	relay.StartRelay(conn, stream)
}

func (a *Agent) handleListenerClose(codec *wire.Codec, req *wire.ListenerCloseRequest) {
	// Listeners are closed when their goroutine's stream is torn down; this
	// message simply acknowledges. A production build would index listeners by
	// id and close the matching net.Listener here.
	_ = codec.Encode(wire.ListenerCloseResponse{})
}

func collectInterfaces() []wire.NetInterface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]wire.NetInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		var addrs []string
		if a, err := iface.Addrs(); err == nil {
			for _, ad := range a {
				addrs = append(addrs, ad.String())
			}
		}
		out = append(out, wire.NetInterface{
			Index:        iface.Index,
			MTU:          iface.MTU,
			Name:         iface.Name,
			HardwareAddr: iface.HardwareAddr.String(),
			Flags:        uint(iface.Flags),
			Addresses:    addrs,
		})
	}
	return out
}
