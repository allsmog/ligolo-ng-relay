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

// Package wire defines the Ligolo v2 control protocol: a self-describing,
// length-prefixed, versioned frame format carrying msgpack payloads.
//
// The legacy protocol wrote a bare msgpack type byte followed by a msgpack body
// with no magic, no explicit length and no version, which made framing errors
// and protocol evolution fragile. The v2 frame has a fixed 8-byte header:
//
//	magic[2] = 0x4C 0x47 ("LG")
//	version  uint8        protocol version
//	type     uint8        message type
//	length   uint32 (BE)  payload length in bytes
//
// followed by a msgpack-encoded payload. The magic resynchronizes a corrupted
// stream, the explicit length removes reliance on the decoder consuming exactly
// the right number of bytes, and the version enables capability negotiation.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/shamaton/msgpack/v2"
)

// ProtocolVersion is the current Ligolo control-protocol version.
const ProtocolVersion uint8 = 2

var magic = [2]byte{0x4C, 0x47}

const headerLen = 8

// MaxPayload caps a single control payload to guard against memory abuse.
const MaxPayload = 16 * 1024 * 1024

var (
	ErrBadMagic    = errors.New("wire: bad frame magic")
	ErrPayloadSize = errors.New("wire: payload exceeds maximum size")
)

// Encoder writes framed control messages to w.
type Encoder struct {
	w io.Writer
}

func NewEncoder(w io.Writer) *Encoder { return &Encoder{w: w} }

// Encode marshals payload (msgpack) and writes a framed message. The message
// type is derived from the payload's Go type.
func (e *Encoder) Encode(payload interface{}) error {
	msgType, err := typeOf(payload)
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
	var hdr [headerLen]byte
	hdr[0], hdr[1] = magic[0], magic[1]
	hdr[2] = ProtocolVersion
	hdr[3] = uint8(msgType)
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(body)))
	if _, err := e.w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = e.w.Write(body)
	return err
}

// Decoder reads framed control messages from r.
type Decoder struct {
	r io.Reader
	// Version is the protocol version seen on the most recently decoded frame.
	Version uint8
	// Payload holds the most recently decoded message (a pointer to one of the
	// message structs in this package).
	Payload interface{}
}

func NewDecoder(r io.Reader) *Decoder { return &Decoder{r: r} }

// Decode reads the next framed message into d.Payload.
func (d *Decoder) Decode() error {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(d.r, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != magic[0] || hdr[1] != magic[1] {
		return ErrBadMagic
	}
	d.Version = hdr[2]
	msgType := MessageType(hdr[3])
	length := binary.BigEndian.Uint32(hdr[4:])
	if length > MaxPayload {
		return ErrPayloadSize
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(d.r, body); err != nil {
		return err
	}
	p, err := newOf(msgType)
	if err != nil {
		return err
	}
	if err := msgpack.Unmarshal(body, p); err != nil {
		return fmt.Errorf("wire: decode payload type %d: %w", msgType, err)
	}
	d.Payload = p
	return nil
}

// Codec bundles an Encoder and Decoder over a single read/writer (e.g. a
// transport stream), mirroring the legacy EncoderDecoder helper.
type Codec struct {
	*Encoder
	*Decoder
}

func NewCodec(rw io.ReadWriter) *Codec {
	return &Codec{Encoder: NewEncoder(rw), Decoder: NewDecoder(rw)}
}
