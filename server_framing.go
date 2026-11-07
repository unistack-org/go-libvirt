// Copyright 2026 The go-libvirt Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package libvirt

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/unistack-org/go-libvirt/internal/constants"
	xdr "github.com/unistack-org/go-libvirt/internal/go-xdr/xdr2"
)

// Wire framing constants for the server side (libvirt's sunrpc transport).
const (
	// maxServerPacketSize is libvirt's payload cap per fragment.
	maxServerPacketSize = 4 * 1024 * 1024
	// lastFragmentBit marks the final (usually only) fragment of a message.
	lastFragmentBit = 0x80000000

	serverHeaderSize = 24

	// keepaliveProgram is REMOTE_KEEPALIVE_PROGRAM (0x20009002); a libvirt
	// client sends KEEPALIVE (proc 0) on it periodically once connected.
	keepaliveProgram  = uint32(0x20009002)
	keepaliveVersion  = uint32(0)
	keepaliveProcPing = uint32(0)
)

// serverPacket is one decoded RPC frame: the 24-byte header fields plus payload.
type serverPacket struct {
	program   uint32
	version   uint32
	procedure uint32
	pktType   uint32
	serial    uint32
	status    uint32
	payload   []byte

	// plain is true when the sender did not set the last-fragment bit in
	// the length word. Stock libvirt (virsh) always sets the bit and its
	// length counts the fragment body only (header+payload, without the
	// 4-byte length word). This library's own client sets Len =
	// 4+24+payload and never sets the fragment bit (see socket.Socket).
	// The server accepts both conventions and echoes the peer's
	// convention back in replies.
	plain bool
}

// readServerPacket reads one length-prefixed fragment from r. Multi-fragment
// messages are not expected from libvirt over TCP (it caps payloads at
// ~4 MiB and fragments are rare); a continuation fragment is an error.
func readServerPacket(r io.Reader) (*serverPacket, error) {
	var lenbuf [4]byte
	if _, err := io.ReadFull(r, lenbuf[:]); err != nil {
		return nil, err
	}
	v := binary.BigEndian.Uint32(lenbuf[:])
	plain := v&lastFragmentBit == 0
	size := v &^ lastFragmentBit
	body := size
	if plain {
		// go-libvirt convention: the length word counts itself too.
		body = size - 4
	}
	if body < serverHeaderSize || body > maxServerPacketSize+serverHeaderSize {
		return nil, fmt.Errorf("libvirt: bad packet size %d", size)
	}
	// body is the fragment size (24-byte header + payload), excluding the
	// 4-byte length word.
	buf := make([]byte, body)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	p := &serverPacket{
		program:   binary.BigEndian.Uint32(buf[0:4]),
		version:   binary.BigEndian.Uint32(buf[4:8]),
		procedure: binary.BigEndian.Uint32(buf[8:12]),
		pktType:   binary.BigEndian.Uint32(buf[12:16]),
		serial:    binary.BigEndian.Uint32(buf[16:20]),
		status:    binary.BigEndian.Uint32(buf[20:24]),
		plain:     plain,
	}
	if len(buf) > serverHeaderSize {
		p.payload = buf[serverHeaderSize:]
	}
	return p, nil
}

// writeServerPacket serialises one fragment and flushes it.
func writeServerPacket(w *bufio.Writer, p *serverPacket) error {
	if len(p.payload) > maxServerPacketSize {
		return fmt.Errorf("libvirt: payload too large (%d bytes)", len(p.payload))
	}
	var hdr [4 + serverHeaderSize]byte
	sizeWord := uint32(serverHeaderSize + len(p.payload))
	if p.plain {
		sizeWord += 4 // go-libvirt counts the length word itself, no fragment bit
	} else {
		sizeWord |= lastFragmentBit
	}
	binary.BigEndian.PutUint32(hdr[0:4], sizeWord)
	binary.BigEndian.PutUint32(hdr[4:8], p.program)
	binary.BigEndian.PutUint32(hdr[8:12], p.version)
	binary.BigEndian.PutUint32(hdr[12:16], p.procedure)
	binary.BigEndian.PutUint32(hdr[16:20], p.pktType)
	binary.BigEndian.PutUint32(hdr[20:24], p.serial)
	binary.BigEndian.PutUint32(hdr[24:28], p.status)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(p.payload) > 0 {
		if _, err := w.Write(p.payload); err != nil {
			return err
		}
	}
	return w.Flush()
}

// replyOK answers a call with StatusOK and the (pre-encoded) payload.
func (c *serverConn) replyOK(p *serverPacket, payload []byte) error {
	return c.replyOKOn(uint32(constants.Program), constants.ProtocolVersion, p, payload)
}

// replyOKOn answers on an explicit program (e.g. the keepalive program).
func (c *serverConn) replyOKOn(program, version uint32, p *serverPacket, payload []byte) error {
	return writeServerPacket(c.w, &serverPacket{
		plain:     p.plain,
		program:   program,
		version:   version,
		procedure: p.procedure,
		pktType:   socketReply,
		serial:    p.serial,
		status:    socketStatusOK,
		payload:   payload,
	})
}

// replyError answers a call with a remote error. code is a libvirt
// remote error code (see const.gen.go); message is free-form.
func (c *serverConn) replyError(p *serverPacket, code ErrorNumber, message string) error {
	return writeServerPacket(c.w, &serverPacket{
		plain:     p.plain,
		program:   uint32(constants.Program),
		version:   constants.ProtocolVersion,
		procedure: p.procedure,
		pktType:   socketReply,
		serial:    p.serial,
		status:    socketStatusError,
		payload:   encodeRemoteError(code, message),
	})
}

// replyStreamError answers a stream-data packet (Type=Stream) that the
// client sent (used by tunnelled migration, which the server refuses) —
// reply with an error status so the client aborts cleanly.
func (c *serverConn) replyStreamError(p *serverPacket, message string) error {
	return c.replyError(p, ErrNoSupport, message)
}

// Remote error domain: VIR_FROM_REMOTE.
const errDomainRemote = uint32(6)

// encodeRemoteError builds a remote_error payload:
//
//	struct remote_error {
//	    int  code;
//	    u_int domain;
//	    u_char padding;
//	    string message;
//	    int level;
//	    remote_error_info info[REMOTE_PROTOCOL_MESSAGE_FIELD]; // 2 entries
//	    size_t flags;
//	}
//
// The trailing info list + flags are required by libvirt's client-side
// decoder (we send an empty info list).
func encodeRemoteError(code ErrorNumber, message string) []byte {
	var buf bytes.Buffer
	e := xdr.NewEncoder(&buf)
	_, _ = e.Encode(uint32(code))
	_, _ = e.Encode(errDomainRemote)
	_, _ = e.Encode(uint8(0)) // padding
	_, _ = e.Encode(message)
	_, _ = e.Encode(uint32(0)) // level: VIR_ERR_ERROR
	_, _ = e.Encode(uint32(0)) // info<2>: empty list
	_, _ = e.Encode(uint32(0)) // flags size
	return buf.Bytes()
}
