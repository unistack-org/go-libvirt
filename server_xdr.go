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
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	xdr "github.com/unistack-org/go-libvirt/internal/go-xdr/xdr2"
)

// serverEncodeArgs XDR-encodes a struct (mirrors the client-side encode in
// rpc.go).
func serverEncodeArgs(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := xdr.NewEncoder(&buf).Encode(v); err != nil {
		return nil, fmt.Errorf("libvirt: server xdr encode %T: %w", v, err)
	}
	return buf.Bytes(), nil
}

// serverDecodeArgs XDR-decodes a payload into v.
func serverDecodeArgs(payload []byte, v interface{}) error {
	if _, err := xdr.NewDecoder(bytes.NewReader(payload)).Decode(v); err != nil {
		return fmt.Errorf("libvirt: server xdr decode %T: %w", v, err)
	}
	return nil
}

// xdrReader is a cursor over a payload with the small handful of XDR
// primitives the server handlers need, plus lenient handling of this
// library's own 3-byte padding quirk in CONNECT_OPEN (real libvirt/virsh
// sends standard XDR).
type xdrReader struct {
	buf []byte
	off int
}

func newXDRReader(payload []byte) *xdrReader { return &xdrReader{buf: payload} }

func (r *xdrReader) remaining() int { return len(r.buf) - r.off }

func (r *xdrReader) u32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, fmt.Errorf("libvirt: short read for u32")
	}
	v := binary.BigEndian.Uint32(r.buf[r.off:])
	r.off += 4
	return v, nil
}

func (r *xdrReader) u64() (uint64, error) {
	hi, err := r.u32()
	if err != nil {
		return 0, err
	}
	lo, err := r.u32()
	if err != nil {
		return 0, err
	}
	return uint64(hi)<<32 | uint64(lo), nil
}

func (r *xdrReader) i32() (int32, error) {
	v, err := r.u32()
	return int32(v), err
}

func (r *xdrReader) str() (string, error) {
	n, err := r.u32()
	if err != nil {
		return "", err
	}
	if int(n) > r.remaining() {
		return "", fmt.Errorf("libvirt: string length %d overruns payload", n)
	}
	s := string(r.buf[r.off : r.off+int(n)])
	r.off += int(n)
	if pad := int(n) % 4; pad != 0 {
		r.off += 4 - pad
	}
	return s, nil
}

// optString decodes remote_string (opt_string): u32 present flag, then the
// string when present.
func (r *xdrReader) optString() (string, bool, error) {
	present, err := r.u32()
	if err != nil {
		return "", false, err
	}
	if present == 0 {
		return "", false, nil
	}
	s, err := r.str()
	return s, true, nil
}

// opaque decodes a variable-length opaque<> (u32 length + data + pad).
func (r *xdrReader) opaque() ([]byte, error) {
	n, err := r.u32()
	if err != nil {
		return nil, err
	}
	if int(n) > r.remaining() {
		return nil, fmt.Errorf("libvirt: opaque length %d overruns payload", n)
	}
	b := make([]byte, int(n))
	copy(b, r.buf[r.off:r.off+int(n)])
	r.off += int(n)
	if pad := int(n) % 4; pad != 0 {
		r.off += 4 - pad
	}
	return b, nil
}

// decodeServerTypedParams decodes a remote_typed_param list (as sent by
// Migrate*3Params procs). The generated TypedParamValue tagged union cannot
// be xdr-decoded directly, so the list is decoded field by field.
func decodeServerTypedParams(r *xdrReader) ([]TypedParam, error) {
	n, err := r.u32()
	if err != nil {
		return nil, err
	}
	if n > 512 {
		return nil, fmt.Errorf("libvirt: typed param count %d too large", n)
	}
	out := make([]TypedParam, 0, n)
	for i := uint32(0); i < n; i++ {
		field, err := r.str()
		if err != nil {
			return nil, err
		}
		d, err := r.u32()
		if err != nil {
			return nil, err
		}
		var pv TypedParamValue
		switch d {
		case 1: // int
			v, err := r.i32()
			if err != nil {
				return nil, err
			}
			pv = *NewTypedParamValueInt(v)
		case 2: // uint
			v, err := r.u32()
			if err != nil {
				return nil, err
			}
			pv = *NewTypedParamValueUint(v)
		case 3: // llong
			v, err := r.u64()
			if err != nil {
				return nil, err
			}
			pv = *NewTypedParamValueLlong(int64(v))
		case 4: // ullong
			v, err := r.u64()
			if err != nil {
				return nil, err
			}
			pv = *NewTypedParamValueUllong(v)
		case 5: // double
			v, err := r.u64()
			if err != nil {
				return nil, err
			}
			pv = *NewTypedParamValueDouble(math.Float64frombits(v))
		case 6: // boolean
			v, err := r.i32()
			if err != nil {
				return nil, err
			}
			pv = *NewTypedParamValueBoolean(v)
		case 7: // string
			v, err := r.str()
			if err != nil {
				return nil, err
			}
			pv = *NewTypedParamValueString(v)
		default:
			return nil, fmt.Errorf("libvirt: unknown TypedParam value discriminant %d for %q", d, field)
		}
		out = append(out, TypedParam{Field: field, Value: pv})
	}
	return out, nil
}

// int8ToBytes converts a []int8 (libvirt's byte arrays on the wire) to []byte.
func int8ToBytes(d []int8) []byte {
	b := make([]byte, len(d))
	for i, v := range d {
		b[i] = byte(v)
	}
	return b
}

// bytesToInt8 converts []byte to libvirt's []int8 wire representation.
func bytesToInt8(b []byte) []int8 {
	d := make([]int8, len(b))
	for i, v := range b {
		d[i] = int8(v)
	}
	return d
}
