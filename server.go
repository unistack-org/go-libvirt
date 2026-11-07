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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/unistack-org/go-libvirt/internal/constants"
)

// Socket-level packet type / status aliases used by the server framing.
// The public constants of the same name live in the socket package; the
// root package re-declares the numeric values (they are wire constants).
const (
	socketCall     = uint32(0)
	socketReply    = uint32(1)
	socketStream   = uint32(3)
	socketStatusOK = uint32(0)
)

const socketStatusError = uint32(1)

// serverRPCError is a handler-level failure converted into a remote_error
// reply.
type serverRPCError struct {
	code ErrorNumber
	msg  string
}

func (e *serverRPCError) Error() string { return e.msg }

// Server is an incoming libvirt-RPC endpoint: a server that speaks the
// same wire protocol as libvirtd, so stock clients (virsh, libvirt-go)
// can connect, authenticate, and (for a migration Front) receive incoming
// migrations. One Server listens on one TCP port.
type Server struct {
	// Front drives the hypervisor plane. Required.
	Front Front
	// TokenValidator validates SASL PLAIN credentials. Required unless
	// AllowNoAuth is set.
	TokenValidator TokenValidator
	// AllowNoAuth accepts AUTH_NONE connections without credentials —
	// development/test only.
	AllowNoAuth bool
	// TLSConfig, when non-nil, wraps accepted connections with TLS and
	// performs libvirt's post-handshake 1-byte "client cert verified"
	// exchange.
	TLSConfig *tls.Config
	// Logger receives operational messages; nil uses log.Default().
	Logger *log.Logger
	// IdleTimeout closes connections with no traffic; 0 = 5 minutes.
	IdleTimeout time.Duration
	// Hostname answers CONNECT_GET_HOSTNAME; defaults to os.Hostname().
	Hostname string

	mu      sync.Mutex
	ln      net.Listener
	conns   map[*serverConn]struct{}
	closing bool
	wg      sync.WaitGroup
}

var errServerClosed = errors.New("libvirt: server closed")

// Serve accepts connections on ln and serves them until Close.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.ln != nil {
		s.mu.Unlock()
		return errors.New("libvirt: server already serving")
	}
	s.ln = ln
	s.conns = make(map[*serverConn]struct{})
	s.mu.Unlock()

	for {
		nc, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closing := s.closing
			s.mu.Unlock()
			if closing || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		c, err := s.newConn(nc)
		if err != nil {
			s.logf("libvirt: server: handshake with %s failed: %v", nc.RemoteAddr(), err)
			_ = nc.Close()
			continue
		}
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			_ = nc.Close()
			return nil
		}
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			c.serve()
			s.mu.Lock()
			delete(s.conns, c)
			s.mu.Unlock()
		}()
	}
}

// Close stops accepting and closes all live connections.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closing = true
	ln := s.ln
	conns := make([]*serverConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	var err error
	if ln != nil {
		err = ln.Close()
	}
	for _, c := range conns {
		_ = c.nc.Close()
	}
	s.wg.Wait()
	return err
}

func (s *Server) logf(format string, args ...interface{}) {
	l := s.Logger
	if l == nil {
		l = log.Default()
	}
	l.Printf(format, args...)
}

// newConn prepares one accepted connection: optional TLS (with libvirt's
// post-handshake byte quirk) and bookkeeping.
func (s *Server) newConn(nc net.Conn) (*serverConn, error) {
	c := &serverConn{
		srv:       s,
		sourceIP:  serverHostOf(nc.RemoteAddr()),
		idle:      s.IdleTimeout,
		auth:      &serverAuthState{},
		staged:    make(map[string]string), // domain name → migration id
		stagedXML: make(map[string]string), // domain name → guest XML
	}
	if c.idle == 0 {
		c.idle = 5 * time.Minute
	}
	if s.TLSConfig != nil {
		tc := tls.Server(nc, s.TLSConfig)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("libvirt: server: TLS handshake: %w", err)
		}
		// libvirt's TLS quirk: the server immediately writes one byte
		// 0x01 ("client certificate verified") and then reads (and
		// ignores) the client's single byte. The go-libvirt client only
		// reads our byte; the real libvirt client writes its byte first
		// and then reads ours — write-first ordering satisfies both.
		if _, err := tc.Write([]byte{1}); err != nil {
			return nil, fmt.Errorf("libvirt: server: TLS verify byte write: %w", err)
		}
		var b [1]byte
		// Best-effort: real libvirt clients send their byte, the
		// go-libvirt client does not. Never fail the connection over it.
		_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.ReadFull(tc, b[:])
		_ = tc.SetReadDeadline(time.Time{})
		c.nc = tc
	} else {
		c.nc = nc
	}
	c.w = bufio.NewWriter(c.nc)
	return c, nil
}

func serverHostOf(a net.Addr) string {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.IP.String()
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}

// serverConn is one client (virsh/libvirt/go-libvirt) connection.
type serverConn struct {
	srv      *Server
	nc       net.Conn
	w        *bufio.Writer
	sourceIP string
	idle     time.Duration
	auth     *serverAuthState

	mu        sync.Mutex
	staged    map[string]string // guest name → migration id
	stagedXML map[string]string // guest name → guest XML
	open      bool              // CONNECT_OPEN succeeded
}

func (c *serverConn) serve() {
	defer c.nc.Close()
	r := bufio.NewReader(c.nc)
	for {
		_ = c.nc.SetDeadline(time.Now().Add(c.idle))
		p, err := readServerPacket(r)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				c.srv.logf("libvirt: server: read from %s: %v", c.sourceIP, err)
			}
			return
		}
		if err := c.dispatch(p); err != nil {
			c.srv.logf("libvirt: server: %v", err)
			return
		}
	}
}

// dispatch routes one call packet.
func (c *serverConn) dispatch(p *serverPacket) error {
	if p.pktType == socketStream {
		// Client→server stream data (tunnelled migration): refused.
		return c.replyStreamError(p, "libvirt: server: tunnelled migration is not supported")
	}
	if p.pktType != socketCall {
		return fmt.Errorf("libvirt: server: unexpected packet type %d from %s", p.pktType, c.sourceIP)
	}

	// KEEPALIVE program: answer pings on the same program.
	if p.program == keepaliveProgram {
		return c.replyOKOn(keepaliveProgram, keepaliveVersion, p, nil)
	}
	if p.program != uint32(constants.Program) {
		return c.replyError(p, ErrOperationUnsupported,
			fmt.Sprintf("libvirt: server: unsupported RPC program %#x", p.program))
	}

	// Before SASL completes (or AUTH_NONE is chosen), only AUTH_* calls
	// are allowed, per libvirt's state machine.
	if !c.authOK() && !isAuthProc(p.procedure) && p.procedure != constants.ProcConnectOpen {
		return c.replyError(p, ErrAuthFailed, "libvirt: server: not authenticated")
	}
	// After auth, everything except CONNECT_OPEN/CONNECT_CLOSE requires an
	// open connection.
	c.mu.Lock()
	open := c.open
	c.mu.Unlock()
	if !open && !isAuthProc(p.procedure) && p.procedure != constants.ProcConnectOpen && p.procedure != constants.ProcConnectClose {
		return c.replyError(p, ErrInvalidConn, "libvirt: server: connection not open")
	}

	var payload []byte
	var err0 error
	var herr *serverRPCError
	switch p.procedure {
	case constants.ProcAuthList:
		payload, err0 = c.handleAuthList(p, p.payload)
	case constants.ProcAuthSaslInit:
		payload, err0 = c.handleSaslInit(p, p.payload)
	case constants.ProcAuthSaslStart:
		payload, err0 = c.handleSaslStart(p, p.payload)
	case constants.ProcAuthSaslStep:
		payload, err0 = c.handleSaslStep(p, p.payload)
	case constants.ProcConnectOpen:
		payload, err0 = c.handleConnectOpen(p, p.payload)
	case constants.ProcConnectClose:
		payload, err0 = c.handleConnectClose(p, p.payload)
	case constants.ProcConnectGetVersion:
		payload, err0 = c.handleConnectGetVersion(p, p.payload)
	case constants.ProcConnectGetLibVersion:
		payload, err0 = c.handleConnectGetLibVersion(p, p.payload)
	case constants.ProcConnectGetHostname:
		payload, err0 = c.handleConnectGetHostname(p, p.payload)
	case constants.ProcConnectGetUri:
		payload, err0 = c.handleConnectGetURI(p, p.payload)
	case constants.ProcConnectSupportsFeature:
		payload, err0 = c.handleConnectSupportsFeature(p, p.payload)
	case constants.ProcConnectGetCapabilities:
		payload, err0 = c.handleConnectGetCapabilities(p, p.payload)
	case constants.ProcNodeGetInfo:
		payload, err0 = c.handleNodeGetInfo(p, p.payload)
	case constants.ProcNodeGetMemoryStats:
		payload, err0 = c.handleNodeGetMemoryStats(p, p.payload)
	case constants.ProcConnectListAllDomains:
		payload, err0 = c.handleConnectListAllDomains(p, p.payload)
	case constants.ProcDomainLookupByName:
		payload, err0 = c.handleDomainLookupByName(p, p.payload)
	case constants.ProcDomainGetXMLDesc:
		payload, err0 = c.handleDomainGetXMLDesc(p, p.payload)
	case constants.ProcDomainGetState:
		payload, err0 = c.handleDomainGetState(p, p.payload)
	case constants.ProcDomainMigratePrepare3:
		payload, err0 = c.handleMigratePrepare3(p, p.payload)
	case constants.ProcDomainMigratePrepare3Params:
		payload, err0 = c.handleMigratePrepare3Params(p, p.payload)
	case constants.ProcDomainMigratePrepareTunnel3, constants.ProcDomainMigratePrepareTunnel3Params:
		return c.replyError(p, ErrNoSupport,
			"libvirt: server: tunnelled migration is not supported (migration traffic must go directly to the destination)")
	case constants.ProcDomainMigrateFinish3:
		payload, err0 = c.handleMigrateFinish3(p, p.payload)
	case constants.ProcDomainMigrateFinish3Params:
		payload, err0 = c.handleMigrateFinish3Params(p, p.payload)
	case constants.ProcNodeGetCPUMap:
		payload, err0 = c.handleNodeGetCPUMap(p, p.payload)
	default:
		return c.replyError(p, ErrOperationUnsupported,
			fmt.Sprintf("libvirt: server: unsupported procedure %d", p.procedure))
	}

	if err0 != nil {
		if errors.As(err0, &herr) {
			return c.replyError(p, herr.code, herr.msg)
		}
		return c.replyError(p, ErrOperationFailed, err0.Error())
	}
	return c.replyOK(p, payload)
}

func isAuthProc(proc uint32) bool {
	switch proc {
	case constants.ProcAuthList, constants.ProcAuthSaslInit,
		constants.ProcAuthSaslStart, constants.ProcAuthSaslStep:
		return true
	}
	return false
}

func (c *serverConn) authOK() bool {
	return c.srv.AllowNoAuth || c.auth.complete
}

// migrationFor returns the staged migration id for a domain name.
func (c *serverConn) migrationFor(name string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id, ok := c.staged[name]
	return id, ok
}

// libvirtServerVersion is the libvirt version the server advertises
// (encoded as major*1000000 + minor*1000 + micro, virVersionEncode).
const libvirtServerVersion = uint64(10 * 1000000) // 10.0.0
