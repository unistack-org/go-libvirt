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
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// handleConnectOpen accepts CONNECT_OPEN (proc 1) and its nameless variant.
// Two wire dialects must be tolerated:
//
//   - real libvirt/virsh: remote_connect_open_args {opt_string name; u32 flags}
//   - this library's client: {padding [3]byte{1,0,0}; string name; u32 flags}
//     (its initLibvirtComms prepends 3 pad bytes).
//
// Both are handled by probing for the client pad prefix.
func (c *serverConn) handleConnectOpen(_ *serverPacket, payload []byte) ([]byte, error) {
	if !c.authOK() {
		return nil, &serverRPCError{code: ErrAuthFailed, msg: "libvirt: server: authentication required"}
	}
	r := newXDRReader(payload)
	// go-libvirt client dialect: 3 pad bytes {1,0,0} precede the name length u32.
	if len(payload) >= 3 && payload[0] == 1 && payload[1] == 0 && payload[2] == 0 {
		r = newXDRReader(payload[3:])
	}
	if r.remaining() >= 4 {
		// opt_string: presence flag then string; virsh sends present=0.
		if _, _, err := r.optString(); err != nil {
			return nil, &serverRPCError{code: ErrInvalidArg, msg: "libvirt: server: malformed CONNECT_OPEN: " + err.Error()}
		}
	}
	c.mu.Lock()
	c.open = true
	c.mu.Unlock()
	c.srv.logf("libvirt: server: connection opened from %s", c.sourceIP)
	return nil, nil
}

func (c *serverConn) handleConnectClose(_ *serverPacket, _ []byte) ([]byte, error) {
	c.mu.Lock()
	c.open = false
	c.mu.Unlock()
	return nil, nil
}

func (c *serverConn) handleConnectGetVersion(_ *serverPacket, _ []byte) ([]byte, error) {
	// HyperVisor version: QEMU 8.2.0 → 8002000 (virVersionEncode-style).
	return serverEncodeArgs(&ConnectGetVersionRet{HvVer: 8 * 1000000})
}

func (c *serverConn) handleConnectGetLibVersion(_ *serverPacket, _ []byte) ([]byte, error) {
	return serverEncodeArgs(&ConnectGetLibVersionRet{LibVer: libvirtServerVersion})
}

func (c *serverConn) handleConnectGetHostname(_ *serverPacket, _ []byte) ([]byte, error) {
	hn := c.srv.Hostname
	if hn == "" {
		hn, _ = os.Hostname()
	}
	return serverEncodeArgs(&ConnectGetHostnameRet{Hostname: hn})
}

func (c *serverConn) handleConnectGetURI(_ *serverPacket, _ []byte) ([]byte, error) {
	return serverEncodeArgs(&ConnectGetUriRet{Uri: "qemu:///system"})
}

// featureSupported answers CONNECT_SUPPORTS_FEATURE. Indices are libvirt's
// virConnectSupportsFeatureFeature; we advertise the migration-relevant
// set and deny the rest.
func featureSupported(f int32) int32 {
	supported := map[int32]bool{
		1:  true, // 64-bit
		4:  true, // pci
		5:  true, // hyperv
		6:  true, // kvm to kvm migrate
		7:  true, // 64-bit file
		9:  true, // usb
		15: true, // net
		16: true, // host allows migration
		19: true, // resize-mem
		21: true, // file locking
		27: true, // lifecycle events
		32: true, // agents
	}
	if supported[f] {
		return 1
	}
	return 0
}

func (c *serverConn) handleConnectSupportsFeature(_ *serverPacket, payload []byte) ([]byte, error) {
	var args ConnectSupportsFeatureArgs
	if err := serverDecodeArgs(payload, &args); err != nil {
		return nil, err
	}
	return serverEncodeArgs(&ConnectSupportsFeatureRet{Supported: featureSupported(args.Feature)})
}

func (c *serverConn) handleConnectGetCapabilities(_ *serverPacket, _ []byte) ([]byte, error) {
	caps, err := c.srv.Front.Capabilities()
	if err != nil {
		return nil, err
	}
	return serverEncodeArgs(&ConnectGetCapabilitiesRet{Capabilities: caps})
}

func (c *serverConn) handleNodeGetInfo(_ *serverPacket, _ []byte) ([]byte, error) {
	ni := c.srv.Front.GetNodeInfo()
	var model [32]int8
	for i := 0; i < len(ni.Model) && i < 31; i++ {
		model[i] = int8(ni.Model[i])
	}
	return serverEncodeArgs(&NodeGetInfoRet{
		Model:   model,
		Memory:  ni.Memory,
		Cpus:    ni.CPUs,
		Mhz:     ni.MHz,
		Nodes:   ni.Nodes,
		Sockets: ni.Sockets,
		Cores:   ni.Cores,
		Threads: ni.Threads,
	})
}

func (c *serverConn) handleNodeGetMemoryStats(_ *serverPacket, _ []byte) ([]byte, error) {
	ni := c.srv.Front.GetNodeInfo()
	free := ni.Memory / 2
	params := []NodeGetMemoryStats{
		{Field: "memory-total", Value: ni.Memory},
		{Field: "memory-free", Value: free},
	}
	return serverEncodeArgs(&NodeGetMemoryStatsRet{Params: params, Nparams: int32(len(params))})
}

func (c *serverConn) handleNodeGetCPUMap(_ *serverPacket, _ []byte) ([]byte, error) {
	ni := c.srv.Front.GetNodeInfo()
	n := int(ni.CPUs)
	if n < 1 {
		n = 1
	}
	cpumap := make([]byte, (n+7)/8)
	for i := 0; i < n; i++ {
		cpumap[i/8] |= 1 << uint(i%8)
	}
	return serverEncodeArgs(&NodeGetCPUMapRet{Cpumap: cpumap, Online: uint32(n), Ret: int32(n)})
}

// stagedDomain returns the synthetic Domain for a guest name known to this
// connection (a staged migration).
func (c *serverConn) stagedDomain(name string) (Domain, bool) {
	c.mu.Lock()
	id, ok := c.staged[name]
	c.mu.Unlock()
	if !ok {
		return Domain{}, false
	}
	return domainFromNameID(name, id), true
}

// domainFromNameID builds a deterministic Domain (ID = -1: not running
// locally, correct for an incoming guest) from name + migration id; the
// UUID is derived from the migration id so Prepare and Finish agree.
func domainFromNameID(name, id string) Domain {
	var u UUID
	// FNV-1a over the migration id, spread across 16 bytes.
	var h uint64 = 14695981039346656037
	for i := 0; i < len(id); i++ {
		h ^= uint64(id[i])
		h *= 1099511628211
	}
	for i := 0; i < 16; i++ {
		u[i] = byte(h >> (8 * (i % 8)))
		h ^= h >> 7
	}
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return Domain{Name: name, UUID: u, ID: -1}
}

func (c *serverConn) handleDomainLookupByName(_ *serverPacket, payload []byte) ([]byte, error) {
	var args DomainLookupByNameArgs
	if err := serverDecodeArgs(payload, &args); err != nil {
		return nil, err
	}
	dom, ok := c.stagedDomain(args.Name)
	if !ok {
		return nil, &serverRPCError{code: ErrNoDomain, msg: fmt.Sprintf("libvirt: server: no incoming domain %q", args.Name)}
	}
	return serverEncodeArgs(&DomainLookupByNameRet{Dom: dom})
}

func (c *serverConn) handleDomainGetXMLDesc(_ *serverPacket, payload []byte) ([]byte, error) {
	var args DomainGetXMLDescArgs
	if err := serverDecodeArgs(payload, &args); err != nil {
		return nil, err
	}
	if _, ok := c.stagedDomain(args.Dom.Name); !ok {
		return nil, &serverRPCError{code: ErrNoDomain, msg: fmt.Sprintf("libvirt: server: no incoming domain %q", args.Dom.Name)}
	}
	c.mu.Lock()
	xmlDesc := c.stagedXML[args.Dom.Name]
	c.mu.Unlock()
	if xmlDesc == "" {
		return nil, &serverRPCError{code: ErrNoDomain, msg: "libvirt: server: guest XML not staged"}
	}
	return serverEncodeArgs(&DomainGetXMLDescRet{XML: xmlDesc})
}

func (c *serverConn) handleDomainGetState(_ *serverPacket, payload []byte) ([]byte, error) {
	var args DomainGetStateArgs
	if err := serverDecodeArgs(payload, &args); err != nil {
		return nil, err
	}
	if _, ok := c.stagedDomain(args.Dom.Name); !ok {
		return nil, &serverRPCError{code: ErrNoDomain, msg: fmt.Sprintf("libvirt: server: no incoming domain %q", args.Dom.Name)}
	}
	// VIR_DOMAIN_BLOCKED (5): domain is being migrated in.
	return serverEncodeArgs(&DomainGetStateRet{State: 5, Reason: 0})
}

func (c *serverConn) handleConnectListAllDomains(_ *serverPacket, _ []byte) ([]byte, error) {
	c.mu.Lock()
	doms := make([]Domain, 0, len(c.staged))
	for name, id := range c.staged {
		doms = append(doms, domainFromNameID(name, id))
	}
	c.mu.Unlock()
	return serverEncodeArgs(&ConnectListAllDomainsRet{Domains: doms, Ret: uint32(len(doms))})
}

// handleMigratePrepare3 implements proc 214.
func (c *serverConn) handleMigratePrepare3(_ *serverPacket, payload []byte) ([]byte, error) {
	var args DomainMigratePrepare3Args
	if err := serverDecodeArgs(payload, &args); err != nil {
		return nil, err
	}
	var dname string
	if len(args.Dname) > 0 {
		dname = args.Dname[0]
	}
	return c.prepare3(dname, args.Flags, args.Bandwidth, args.DomXML, args.CookieIn, nil)
}

func (c *serverConn) handleMigratePrepare3Params(_ *serverPacket, payload []byte) ([]byte, error) {
	// Hand-decoded: Params is []TypedParam whose tagged-union Value xdr
	// cannot decode directly into the generated struct.
	r := newXDRReader(payload)
	params, err := decodeServerTypedParams(r)
	if err != nil {
		return nil, &serverRPCError{code: ErrInvalidArg, msg: "libvirt: server: prepare-params: " + err.Error()}
	}
	cookie, err := r.opaque()
	if err != nil {
		return nil, &serverRPCError{code: ErrInvalidArg, msg: "libvirt: server: prepare-params cookie: " + err.Error()}
	}
	flags, err := r.u32()
	if err != nil {
		return nil, &serverRPCError{code: ErrInvalidArg, msg: "libvirt: server: prepare-params flags: " + err.Error()}
	}

	var dname, domXML string
	var bandwidth uint64
	lite := typedParamsLite(params)
	for _, tp := range lite {
		switch tp.Field {
		case "name", "dest_name":
			dname = tp.String
		case "xml", "dest_xml":
			domXML = tp.String
		case "bandwidth":
			bandwidth = uint64(tp.Int)
		}
	}
	return c.prepare3(dname, uint64(flags), bandwidth, domXML, cookie, lite)
}

// prepare3 is the shared body of MIGRATE_PREPARE3 / _PARAMS.
func (c *serverConn) prepare3(dname string, flags, bandwidth uint64, domXML string, cookieIn []byte, lite []TypedParamLite) ([]byte, error) {
	if domXML == "" {
		return nil, &serverRPCError{code: ErrInvalidArg, msg: "libvirt: server: empty guest XML in prepare"}
	}
	if err := ValidateGuestXML(domXML); err != nil {
		return nil, &serverRPCError{code: ErrOperationFailed, msg: err.Error()}
	}
	name := dname
	if name == "" {
		name = guestNameFromXML(domXML)
	}
	if name == "" {
		return nil, &serverRPCError{code: ErrInvalidArg, msg: "libvirt: server: no domain name (dname absent, XML has no <name>)"}
	}
	migID := newMigrationID()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := c.srv.Front.Prepare(ctx, PrepareRequest{
		Principal:   c.auth.principal,
		SourceIP:    c.sourceIP,
		DomainName:  name,
		Flags:       flags,
		Bandwidth:   bandwidth,
		GuestXML:    domXML,
		Params:      lite,
		MigrationID: migID,
	})
	if err != nil {
		return nil, &serverRPCError{code: ErrOperationFailed, msg: "libvirt: server: prepare: " + err.Error()}
	}
	c.mu.Lock()
	c.staged[name] = migID
	c.stagedXML[name] = domXML
	c.mu.Unlock()
	c.srv.logf("libvirt: server: staged migration %s for %q from %s → dest %s", migID, name, c.sourceIP, res.URIOut)
	return serverEncodeArgs(&DomainMigratePrepare3Ret{
		CookieOut: res.CookieOut,
		UriOut:    OptString{res.URIOut},
	})
}

// handleMigrateFinish3 implements proc 217.
func (c *serverConn) handleMigrateFinish3(_ *serverPacket, payload []byte) ([]byte, error) {
	var args DomainMigrateFinish3Args
	if err := serverDecodeArgs(payload, &args); err != nil {
		return nil, err
	}
	return c.finish3(args.Dname, args.CookieIn, args.Flags, args.Cancelled != 0, nil)
}

func (c *serverConn) handleMigrateFinish3Params(_ *serverPacket, payload []byte) ([]byte, error) {
	r := newXDRReader(payload)
	params, err := decodeServerTypedParams(r)
	if err != nil {
		return nil, &serverRPCError{code: ErrInvalidArg, msg: "libvirt: server: finish-params: " + err.Error()}
	}
	cookie, err := r.opaque()
	if err != nil {
		return nil, &serverRPCError{code: ErrInvalidArg, msg: "libvirt: server: finish-params cookie: " + err.Error()}
	}
	flags, err := r.u32()
	if err != nil {
		return nil, &serverRPCError{code: ErrInvalidArg, msg: "libvirt: server: finish-params flags: " + err.Error()}
	}
	cancelled, err := r.i32()
	if err != nil {
		return nil, &serverRPCError{code: ErrInvalidArg, msg: "libvirt: server: finish-params cancelled: " + err.Error()}
	}
	var dname string
	lite := typedParamsLite(params)
	for _, tp := range lite {
		switch tp.Field {
		case "dest_name", "name", "domain_name":
			dname = tp.String
		}
	}
	return c.finish3(dname, cookie, uint64(flags), cancelled != 0, lite)
}

// finish3 is the shared body of MIGRATE_FINISH3 / _PARAMS.
func (c *serverConn) finish3(dname string, cookieIn []byte, flags uint64, cancelled bool, lite []TypedParamLite) ([]byte, error) {
	migID, ok := c.migrationFor(dname)
	if !ok {
		return nil, &serverRPCError{code: ErrNoDomain, msg: fmt.Sprintf("libvirt: server: no staged migration for %q", dname)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := c.srv.Front.Finish(ctx, FinishRequest{
		Principal:   c.auth.principal,
		SourceIP:    c.sourceIP,
		MigrationID: migID,
		DomainName:  dname,
		Cancelled:   cancelled,
		CookieIn:    cookieIn,
		Flags:       flags,
		Params:      lite,
	})
	if err != nil {
		return nil, &serverRPCError{code: ErrOperationFailed, msg: "libvirt: server: finish: " + err.Error()}
	}
	c.mu.Lock()
	delete(c.staged, dname)
	delete(c.stagedXML, dname)
	c.mu.Unlock()
	c.srv.logf("libvirt: server: migration %s for %q finished (cancelled=%v)", migID, dname, cancelled)
	return serverEncodeArgs(&DomainMigrateFinish3Ret{
		Dom:       Domain{Name: res.DomainName, UUID: res.DomainUUID, ID: -1},
		CookieOut: nil,
	})
}

// typedParamsLite flattens TypedParams for the Front.
func typedParamsLite(params []TypedParam) []TypedParamLite {
	out := make([]TypedParamLite, 0, len(params))
	for _, p := range params {
		tp := TypedParamLite{Field: p.Field}
		switch p.Value.D {
		case 1: // int
			if v, ok := p.Value.I.(int32); ok {
				tp.Kind, tp.Int = "int", int64(v)
			}
		case 2: // uint
			if v, ok := p.Value.I.(uint32); ok {
				tp.Kind, tp.Int = "uint", int64(v)
			}
		case 3: // llong
			if v, ok := p.Value.I.(int64); ok {
				tp.Kind, tp.Int = "llong", v
			}
		case 4: // ullong
			if v, ok := p.Value.I.(uint64); ok {
				tp.Kind, tp.Int = "ullong", int64(v)
			}
		case 5: // double
			if v, ok := p.Value.I.(float64); ok {
				tp.Kind, tp.Float = "double", v
			}
		case 6: // boolean
			if v, ok := p.Value.I.(int32); ok {
				tp.Kind, tp.Bool = "boolean", v != 0
			}
		case 7: // string
			if v, ok := p.Value.I.(string); ok {
				tp.Kind, tp.String = "string", v
			}
		default:
			continue
		}
		if tp.Kind == "" {
			continue
		}
		out = append(out, tp)
	}
	return out
}

// guestNameFromXML extracts <domain><name>…</name> from guest XML.
func guestNameFromXML(guestXML string) string {
	i := strings.Index(guestXML, "<name>")
	if i < 0 {
		return ""
	}
	rest := guestXML[i+len("<name>"):]
	j := strings.Index(rest, "</name>")
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

// newMigrationID returns a sortable, collision-resistant migration id.
func newMigrationID() string {
	return fmt.Sprintf("mig-%d-%06d", time.Now().UnixNano()/1e6, os.Getpid()%1000000)
}
