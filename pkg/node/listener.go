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
	"errors"
	"fmt"
	"net"

	"github.com/nicocha30/ligolo-ng/pkg/relay"
	"github.com/nicocha30/ligolo-ng/pkg/session"
	"github.com/nicocha30/ligolo-ng/pkg/transport"
	"github.com/nicocha30/ligolo-ng/pkg/wire"
	"github.com/sirupsen/logrus"
)

// ReverseListener is a port opened on the agent's network whose inbound
// connections are relayed back to a target reachable from the server. It is the
// server-side counterpart to the agent's handleListener/handleListenerSock.
type ReverseListener struct {
	ID      int32
	Network string
	Addr    string // bind address on the agent
	To      string // redirect target on the server side

	srv    *Server
	sess   *session.Session
	stream transport.Stream
	cancel context.CancelFunc
}

// AddListener asks the agent to open a listener on addr and relays inbound
// connections to `to`. network is "tcp" or "udp".
func (s *Server) AddListener(ctx context.Context, sess *session.Session, network, addr, to string) (*ReverseListener, error) {
	if !wire.Has(sess.Caps, wire.CapReverseListener) {
		return nil, errors.New("agent does not support reverse listeners")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("invalid bind addr: %w", err)
	}
	if _, _, err := net.SplitHostPort(to); err != nil {
		return nil, fmt.Errorf("invalid redirect addr: %w", err)
	}
	t := sess.Transport()
	if t == nil || t.IsClosed() {
		return nil, errors.New("session is offline")
	}
	stream, err := t.Open(ctx)
	if err != nil {
		return nil, err
	}
	codec := wire.NewCodec(stream)
	if err := codec.Encode(wire.ListenerRequest{Network: network, Address: addr}); err != nil {
		stream.Close()
		return nil, err
	}
	if err := codec.Decode(); err != nil {
		stream.Close()
		return nil, err
	}
	resp, ok := codec.Payload.(*wire.ListenerResponse)
	if !ok {
		stream.Close()
		return nil, errors.New("unexpected listener response")
	}
	if resp.Err {
		stream.Close()
		return nil, errors.New(resp.ErrString)
	}

	lctx, cancel := context.WithCancel(ctx)
	rl := &ReverseListener{
		ID: resp.ListenerID, Network: network, Addr: addr, To: to,
		srv: s, sess: sess, stream: stream, cancel: cancel,
	}
	sess.AddListener(&session.Listener{ID: rl.ID, Network: network, Address: addr, To: to})
	go rl.serve(lctx, codec)
	logrus.Infof("reverse listener #%d up: [agent] %s/%s -> [server] %s", rl.ID, addr, network, to)
	return rl, nil
}

func (rl *ReverseListener) serve(ctx context.Context, codec *wire.Codec) {
	if rl.Network == "udp" {
		// The agent relays datagrams directly over the listener stream; bridge it
		// to the redirect target.
		toConn, err := net.Dial("udp", rl.To)
		if err != nil {
			logrus.Errorf("listener #%d: dial %s: %v", rl.ID, rl.To, err)
			rl.stream.Close()
			return
		}
		relay.StartPacketRelay(toConn, rl.stream)
		toConn.Close()
		return
	}

	for {
		if err := codec.Decode(); err != nil {
			return // listener stream closed
		}
		bind, ok := codec.Payload.(*wire.ListenerBindResponse)
		if !ok {
			return
		}
		if bind.Err {
			if ctx.Err() == nil {
				logrus.Debugf("listener #%d ended: %s", rl.ID, bind.ErrString)
			}
			return
		}
		go rl.relayInbound(ctx, bind.SockID)
	}
}

func (rl *ReverseListener) relayInbound(ctx context.Context, sockID int32) {
	t := rl.sess.Transport()
	if t == nil || t.IsClosed() {
		return
	}
	fstream, err := t.Open(ctx)
	if err != nil {
		logrus.Debugf("listener #%d: open forward stream: %v", rl.ID, err)
		return
	}
	codec := wire.NewCodec(fstream)
	if err := codec.Encode(wire.ListenerSockRequest{SockID: sockID}); err != nil {
		fstream.Close()
		return
	}
	if err := codec.Decode(); err != nil {
		fstream.Close()
		return
	}
	if sr, ok := codec.Payload.(*wire.ListenerSockResponse); !ok || sr.Err {
		fstream.Close()
		return
	}

	toConn, err := net.Dial(rl.Network, rl.To)
	connFailed := err != nil
	if encErr := codec.Encode(wire.ListenerSocketReady{Err: connFailed}); encErr != nil {
		fstream.Close()
		if toConn != nil {
			toConn.Close()
		}
		return
	}
	if connFailed {
		logrus.Debugf("listener #%d: dial %s: %v", rl.ID, rl.To, err)
		fstream.Close()
		return
	}
	relay.StartRelay(toConn, fstream)
}

// Stop closes the reverse listener on the agent and stops relaying.
func (rl *ReverseListener) Stop(ctx context.Context) error {
	rl.cancel()
	rl.sess.RemoveListener(rl.ID)
	defer rl.stream.Close()

	t := rl.sess.Transport()
	if t == nil || t.IsClosed() {
		return nil
	}
	stream, err := t.Open(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	codec := wire.NewCodec(stream)
	if err := codec.Encode(wire.ListenerCloseRequest{ListenerID: rl.ID}); err != nil {
		return err
	}
	if err := codec.Decode(); err != nil {
		return err
	}
	if resp, ok := codec.Payload.(*wire.ListenerCloseResponse); ok && resp.Err {
		return errors.New(resp.ErrString)
	}
	return nil
}
