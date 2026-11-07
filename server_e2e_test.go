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

package libvirt_test

import (
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	l "github.com/unistack-org/go-libvirt"
)

const testGuestXML = `<domain type='kvm'>
  <name>web-1</name>
  <uuid>12345678-1234-1234-1234-123456789abc</uuid>
  <memory unit='KiB'>1048576</memory>
  <os><type machine='pc-q35-8.2'>hvm</type></os>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/var/lib/libvirt/images/web-1.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
  </devices>
</domain>`

// startServer brings up a Server with StubFront on a random loopback port.
func startServer(t *testing.T, allowNoAuth bool) (*l.Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &l.Server{
		Front:       l.NewStubFront("127.0.0.1"),
		AllowNoAuth: allowNoAuth,
		Logger:      log.New(testWriter{t}, "libvirt-server: ", 0),
		Hostname:    "unistack-test",
	}
	go func() {
		if err := srv.Serve(ln); err != nil {
			t.Logf("Serve: %v", err)
		}
	}()
	t.Cleanup(func() { _ = srv.Close() })
	return srv, ln.Addr().String()
}

// dialClient connects the go-libvirt client to addr and completes the
// auth + CONNECT_OPEN handshake.
func dialClient(t *testing.T, addr string) *l.Libvirt {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	lv := l.New(conn)
	if err := lv.ConnectToURI(l.ConnectURI("qemu+tcp://" + addr + "/system")); err != nil {
		t.Fatalf("ConnectToURI: %v", err)
	}
	t.Cleanup(func() { _ = lv.Disconnect() })
	return lv
}

func TestE2EConnectAndNodeInfo(t *testing.T) {
	_, addr := startServer(t, true)
	lv := dialClient(t, addr)

	model, memory, cpus, _, _, _, _, _, err := lv.NodeGetInfo()
	if err != nil {
		t.Fatalf("NodeGetInfo: %v", err)
	}
	if cpus != 4 || memory == 0 {
		t.Fatalf("NodeGetInfo mismatch: cpus=%d memory=%d", cpus, memory)
	}
	if got := strings.TrimRight(int8sToString(model[:]), "\x00"); got != "x86_64" {
		t.Fatalf("model = %q", got)
	}

	hn, err := lv.ConnectGetHostname()
	if err != nil || hn != "unistack-test" {
		t.Fatalf("ConnectGetHostname = %q, %v", hn, err)
	}

	caps, err := lv.Capabilities()
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if !strings.Contains(string(caps), "pc-q35-8.2") {
		t.Fatalf("capabilities XML missing machine: %s", caps)
	}
}

func TestE2EPrepareFinishRoundTrip(t *testing.T) {
	_, addr := startServer(t, true)
	lv := dialClient(t, addr)

	// Nothing staged yet.
	doms, _, err := lv.ConnectListAllDomains(1, 0)
	if err != nil {
		t.Fatalf("ConnectListAllDomains: %v", err)
	}
	if len(doms) != 0 {
		t.Fatalf("expected no domains, got %d", len(doms))
	}

	// Prepare3: stage the incoming guest.
	cookieOut, uriOut, err := lv.DomainMigratePrepare3(nil, l.OptString{}, 0, l.OptString{"web-1"}, 0, testGuestXML)
	if err != nil {
		t.Fatalf("DomainMigratePrepare3: %v", err)
	}
	if len(uriOut) != 1 || !strings.HasPrefix(uriOut[0], "127.0.0.1:") {
		t.Fatalf("uriOut = %v", uriOut)
	}
	_ = cookieOut

	// The staged guest must now be listable/lookupable.
	doms, n, err := lv.ConnectListAllDomains(10, 0)
	if err != nil {
		t.Fatalf("ConnectListAllDomains after prepare: %v", err)
	}
	if n != 1 || len(doms) != 1 || doms[0].Name != "web-1" {
		t.Fatalf("domains after prepare: n=%d %+v", n, doms)
	}
	dom, err := lv.DomainLookupByName("web-1")
	if err != nil {
		t.Fatalf("DomainLookupByName: %v", err)
	}
	if dom.Name != "web-1" {
		t.Fatalf("lookup name = %q", dom.Name)
	}

	xmlDesc, err := lv.DomainGetXMLDesc(dom, 0)
	if err != nil {
		t.Fatalf("DomainGetXMLDesc: %v", err)
	}
	if !strings.Contains(xmlDesc, "<name>web-1</name>") {
		t.Fatalf("xml = %q", xmlDesc)
	}

	// Finish3: complete the migration.
	fdom, _, err := lv.DomainMigrateFinish3("web-1", nil, l.OptString{"qemu+tcp://src/"}, l.OptString{}, 0, 0)
	if err != nil {
		t.Fatalf("DomainMigrateFinish3: %v", err)
	}
	if fdom.Name != "web-1" {
		t.Fatalf("finish domain = %+v", fdom)
	}

	// After a successful finish the staging is cleared.
	doms, n, err = lv.ConnectListAllDomains(10, 0)
	if err != nil {
		t.Fatalf("ConnectListAllDomains after finish: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected staging cleared, got %d", n)
	}
}

func TestE2EPrepareRejectsPassthrough(t *testing.T) {
	_, addr := startServer(t, true)
	lv := dialClient(t, addr)

	bad := strings.Replace(testGuestXML, "<devices>", `<devices>
    <hostdev mode='subsystem' type='pci' managed='yes'><source><address domain='0x0000' bus='0x01' slot='0x00' function='0x0'/></source></hostdev>`, 1)
	_, _, err := lv.DomainMigratePrepare3(nil, l.OptString{}, 0, l.OptString{"web-1"}, 0, bad)
	if err == nil {
		t.Fatal("expected Prepare3 to reject VFIO hostdev")
	}
	if !strings.Contains(err.Error(), "VFIO") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestE2EFinishWithoutPrepareFails(t *testing.T) {
	_, addr := startServer(t, true)
	lv := dialClient(t, addr)
	_, _, err := lv.DomainMigrateFinish3("ghost", nil, l.OptString{}, l.OptString{}, 0, 0)
	if err == nil {
		t.Fatal("expected Finish3 for unknown domain to fail")
	}
}

func TestE2ETunnelRefused(t *testing.T) {
	_, addr := startServer(t, true)
	lv := dialClient(t, addr)
	_, err := lv.DomainMigratePrepareTunnel3(nil, strings.NewReader("x"), 0, l.OptString{"web-1"}, 0, testGuestXML)
	if err == nil {
		t.Fatal("expected PrepareTunnel3 to be refused")
	}
}

func TestE2EKeepalive(t *testing.T) {
	_, addr := startServer(t, true)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	call := func(program, proc uint32, serial uint32, payload []byte) {
		b := make([]byte, 0, 28+len(payload))
		b = appendU32(b, 0x80000000|uint32(24+len(payload)))
		b = appendU32(b, program)
		b = appendU32(b, 1)
		b = appendU32(b, proc)
		b = appendU32(b, 0) // call
		b = appendU32(b, serial)
		b = appendU32(b, 0)
		b = append(b, payload...)
		if _, err := conn.Write(b); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	call(0x20008086, 66, 1, nil) // AUTH_LIST
	resp := readReply(t, conn)
	if resp.status != 0 {
		t.Fatalf("AUTH_LIST reply status = %d", resp.status)
	}
	openPayload := []byte{1, 0, 0} // go-libvirt padding
	openPayload = appendU32(openPayload, uint32(len("qemu:///system")))
	openPayload = append(openPayload, "qemu:///system"...)
	openPayload = appendU32(openPayload, 0) // flags
	call(0x20008086, 1, 2, openPayload)
	if resp = readReply(t, conn); resp.status != 0 {
		t.Fatalf("CONNECT_OPEN reply status = %d", resp.status)
	}
	call(0x20009002, 0, 3, nil) // keepalive ping
	if resp = readReply(t, conn); resp.status != 0 || resp.program != 0x20009002 {
		t.Fatalf("keepalive reply = %+v", resp)
	}
}

func TestE2EAuthRequiredWhenNoAuthDisabled(t *testing.T) {
	_, addr := startServer(t, false)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// AUTH_LIST: must advertise SASL only (no NONE).
	b := make([]byte, 0, 28)
	b = appendU32(b, 0x80000000|24)
	b = appendU32(b, 0x20008086)
	b = appendU32(b, 1)
	b = appendU32(b, 66)
	b = appendU32(b, 0)
	b = appendU32(b, 1)
	b = appendU32(b, 0)
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp := readReply(t, conn)
	if resp.status != 0 {
		t.Fatalf("AUTH_LIST status = %d", resp.status)
	}
	if len(resp.payload) < 8 {
		t.Fatalf("short AUTH_LIST payload: %v", resp.payload)
	}
	count := beU32(resp.payload)
	if count != 1 || beU32(resp.payload[4:]) != 1 { // exactly [SASL]
		t.Fatalf("auth types = %v", resp.payload)
	}
	// CONNECT_OPEN without SASL → must be rejected with an auth error.
	b = b[:0]
	b = appendU32(b, 0x80000000|24)
	b = appendU32(b, 0x20008086)
	b = appendU32(b, 1)
	b = appendU32(b, 1)
	b = appendU32(b, 0)
	b = appendU32(b, 2)
	b = appendU32(b, 0)
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("write open: %v", err)
	}
	resp = readReply(t, conn)
	if resp.status != 1 {
		t.Fatalf("expected error reply, got status %d", resp.status)
	}
}

// --- tiny raw-RPC helpers for the keepalive/auth tests ---

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func beU32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

type rawReply struct {
	program uint32
	serial  uint32
	status  uint32
	payload []byte
}

func readReply(t *testing.T, c net.Conn) rawReply {
	t.Helper()
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatalf("read len: %v", err)
	}
	size := beU32(hdr) &^ 0x80000000
	buf := make([]byte, size)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read body: %v", err)
	}
	r := rawReply{
		program: beU32(buf[0:4]),
		serial:  beU32(buf[16:20]),
		status:  beU32(buf[20:24]),
	}
	if len(buf) > 24 {
		r.payload = buf[24:]
	}
	return r
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func int8sToString(b []int8) string {
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = byte(v)
	}
	return string(out)
}
