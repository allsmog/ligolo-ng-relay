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
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/nicocha30/ligolo-ng/pkg/transport"
)

// dgramHub multiplexes many UDP flows over a single QUIC datagram channel.
//
// QUIC datagrams are connection-scoped, so each datagram is framed as
// flowID(4 bytes, BE) || payload. One receive loop demultiplexes incoming
// datagrams to the per-flow flowConn. Carrying UDP as datagrams avoids the
// per-flow stream overhead and the head-of-line blocking of reliable streams,
// which matches UDP's own delivery semantics.
type dgramHub struct {
	sess   transport.DatagramSession
	ctx    context.Context
	cancel context.CancelFunc

	mu    sync.Mutex
	flows map[uint32]*flowConn
}

func newDgramHub(sess transport.DatagramSession) *dgramHub {
	ctx, cancel := context.WithCancel(context.Background())
	h := &dgramHub{sess: sess, ctx: ctx, cancel: cancel, flows: make(map[uint32]*flowConn)}
	go h.readLoop()
	return h
}

func (h *dgramHub) readLoop() {
	for {
		b, err := h.sess.ReceiveDatagram(h.ctx)
		if err != nil {
			h.closeAll()
			return
		}
		if len(b) < 4 {
			continue
		}
		flowID := binary.BigEndian.Uint32(b[:4])
		h.mu.Lock()
		fc := h.flows[flowID]
		h.mu.Unlock()
		if fc != nil {
			fc.deliver(b[4:])
		}
	}
}

// open registers a flow and returns a net.Conn carrying it over datagrams.
func (h *dgramHub) open(flowID uint32) *flowConn {
	fc := &flowConn{
		hub:    h,
		flowID: flowID,
		inbox:  make(chan []byte, 256),
		closed: make(chan struct{}),
	}
	h.mu.Lock()
	h.flows[flowID] = fc
	h.mu.Unlock()
	return fc
}

func (h *dgramHub) remove(flowID uint32) {
	h.mu.Lock()
	delete(h.flows, flowID)
	h.mu.Unlock()
}

func (h *dgramHub) closeAll() {
	h.mu.Lock()
	for _, fc := range h.flows {
		fc.shut()
	}
	h.flows = make(map[uint32]*flowConn)
	h.mu.Unlock()
}

// Close stops the hub's receive loop and tears down all flows.
func (h *dgramHub) Close() {
	h.cancel()
	h.closeAll()
}

// flowConn is a net.Conn for one UDP flow over the datagram channel, so it can
// be handed to the existing relay (io.Copy) unchanged.
type flowConn struct {
	hub    *dgramHub
	flowID uint32
	inbox  chan []byte
	buf    []byte

	closeOnce sync.Once
	closed    chan struct{}

	rmu      sync.Mutex
	deadline time.Time
}

func (c *flowConn) deliver(p []byte) {
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case c.inbox <- cp:
	case <-c.closed:
	default: // drop on backpressure, like a real UDP socket buffer
	}
}

func (c *flowConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	c.rmu.Lock()
	dl := c.deadline
	c.rmu.Unlock()

	var timer <-chan time.Time
	if !dl.IsZero() {
		t := time.NewTimer(time.Until(dl))
		defer t.Stop()
		timer = t.C
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-timer:
		return 0, &timeoutError{}
	case b := <-c.inbox:
		n := copy(p, b)
		if n < len(b) {
			c.buf = b[n:] // datagram larger than read buffer; keep remainder
		}
		return n, nil
	}
}

func (c *flowConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	frame := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(frame[:4], c.flowID)
	copy(frame[4:], p)
	if err := c.hub.sess.SendDatagram(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *flowConn) shut() { c.closeOnce.Do(func() { close(c.closed) }) }

func (c *flowConn) Close() error {
	c.shut()
	c.hub.remove(c.flowID)
	return nil
}

func (c *flowConn) LocalAddr() net.Addr  { return c.hub.sess.LocalAddr() }
func (c *flowConn) RemoteAddr() net.Addr { return c.hub.sess.RemoteAddr() }

func (c *flowConn) SetDeadline(t time.Time) error {
	c.rmu.Lock()
	c.deadline = t
	c.rmu.Unlock()
	return nil
}
func (c *flowConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *flowConn) SetWriteDeadline(t time.Time) error { return nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "datagram flow: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// MaxDatagramPayload is the largest UDP payload that fits in one QUIC datagram
// after the 4-byte flow header. Larger UDP datagrams will fail to send and that
// flow falls back to being dropped; typical UDP (DNS, etc.) fits comfortably.
const MaxDatagramPayload = 1200 - 4

// bindDatagramFlow relays a local connection (the dialed UDP socket on the
// agent, or the gVisor UDP endpoint on the server) against a datagram flowConn,
// using the setup stream as a bidirectional teardown signal: closing it tells
// the peer the flow has ended, and observing its EOF tears down this side.
func bindDatagramFlow(setup transport.Stream, local net.Conn, fc *flowConn) {
	go func() {
		// Peer closed the setup stream -> tear down this side.
		buf := make([]byte, 1)
		for {
			if _, err := setup.Read(buf); err != nil {
				break
			}
		}
		local.Close()
		fc.Close()
	}()
	// Relay until the local socket or the flow errors, then signal the peer.
	relayConns(local, fc)
	setup.Close()
}

// relayConns is the datagram-flow relay (io.Copy both directions, closing on
// error). It mirrors pkg/relay but is kept local to avoid an import cycle with
// the flowConn type.
func relayConns(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		dst.Close()
		src.Close()
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
}
