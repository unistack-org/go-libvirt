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
	"testing"

	"github.com/unistack-org/go-libvirt/internal/constants"
)

func TestServerPacketRoundTrip(t *testing.T) {
	in := &serverPacket{
		program:   uint32(constants.Program),
		version:   uint32(constants.ProtocolVersion),
		procedure: uint32(constants.ProcDomainMigratePrepare3),
		pktType:   socketCall,
		serial:    0xdeadbeef,
		payload:   []byte{1, 2, 3, 4, 5},
	}
	var buf bytes.Buffer
	if err := writeServerPacket(bufio.NewWriter(&buf), in); err != nil {
		t.Fatalf("writeServerPacket: %v", err)
	}
	out, err := readServerPacket(&buf)
	if err != nil {
		t.Fatalf("readServerPacket: %v", err)
	}
	if out.program != in.program || out.version != in.version || out.procedure != in.procedure ||
		out.pktType != in.pktType || out.serial != in.serial {
		t.Fatalf("header mismatch: got %+v want %+v", out, in)
	}
	if !bytes.Equal(out.payload, in.payload) {
		t.Fatalf("payload mismatch: got %v want %v", out.payload, in.payload)
	}
}

func TestServerPacketRoundTripEmptyPayload(t *testing.T) {
	in := &serverPacket{program: keepaliveProgram, pktType: socketCall, serial: 7}
	var buf bytes.Buffer
	if err := writeServerPacket(bufio.NewWriter(&buf), in); err != nil {
		t.Fatalf("writeServerPacket: %v", err)
	}
	out, err := readServerPacket(&buf)
	if err != nil {
		t.Fatalf("readServerPacket: %v", err)
	}
	if len(out.payload) != 0 || out.serial != 7 {
		t.Fatalf("mismatch: %+v", out)
	}
}

// TestServerPacketRoundTripPlain covers the go-libvirt client convention:
// no last-fragment bit and the length word counts itself.
func TestServerPacketRoundTripPlain(t *testing.T) {
	in := &serverPacket{
		plain:     true,
		program:   uint32(constants.Program),
		version:   uint32(constants.ProtocolVersion),
		procedure: uint32(constants.ProcConnectOpen),
		pktType:   socketCall,
		serial:    42,
		payload:   []byte{9, 8, 7},
	}
	var buf bytes.Buffer
	if err := writeServerPacket(bufio.NewWriter(&buf), in); err != nil {
		t.Fatalf("writeServerPacket: %v", err)
	}
	// length = 4 + 24 + 3, no 0x80000000 bit
	if got := binary.BigEndian.Uint32(buf.Bytes()[:4]); got != 31 {
		t.Fatalf("size word = %d, want 31", got)
	}
	out, err := readServerPacket(&buf)
	if err != nil {
		t.Fatalf("readServerPacket: %v", err)
	}
	if !out.plain || out.serial != 42 || !bytes.Equal(out.payload, in.payload) {
		t.Fatalf("mismatch: got %+v", out)
	}
}

func TestServerReadPacketRejectsBadSize(t *testing.T) {
	var buf bytes.Buffer
	// too small: fragment body of 20 bytes < 24-byte header
	buf.Write([]byte{0x80, 0x00, 0x00, 0x14})
	buf.Write(make([]byte, 20))
	if _, err := readServerPacket(&buf); err == nil {
		t.Fatal("expected error for undersized packet")
	}
}
