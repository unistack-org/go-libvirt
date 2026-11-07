// Copyright 2026 The go-libvirt Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0

package libvirt_test

import (
	"errors"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	l "github.com/unistack-org/go-libvirt"
)

// saslValidator accepts one token and pins the window id in authcid.
type saslValidator struct{ token string }

func (v saslValidator) Validate(authzID, authcid, passwd, sourceIP string) (l.Principal, error) {
	if passwd != v.token {
		return l.Principal{}, errors.New("bad token")
	}
	if authcid != "" && authcid != "win-1" {
		return l.Principal{}, errors.New("bad window")
	}
	return l.Principal{ProjectID: "proj-1", WindowID: "win-1"}, nil
}

func startSASLServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &l.Server{
		Front:          l.NewStubFront("127.0.0.1"),
		TokenValidator: saslValidator{token: "sekrit-token"},
		Logger:         log.New(testWriter{t}, "libvirt-sasl: ", 0),
		Hostname:       "unistack-test",
	}
	go func() {
		if err := srv.Serve(ln); err != nil {
			t.Logf("Serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	return ln.Addr().String()
}

func saslRawCall(t *testing.T, conn net.Conn, program, proc, serial uint32, payload []byte) rawReply {
	t.Helper()
	b := make([]byte, 0, 28+len(payload))
	b = appendU32(b, 0x80000000|uint32(24+len(payload)))
	b = appendU32(b, program)
	b = appendU32(b, 1) // version
	b = appendU32(b, proc)
	b = appendU32(b, 0) // call
	b = appendU32(b, serial)
	b = appendU32(b, 0) // padding
	b = append(b, payload...)
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
	return readReply(t, conn)
}

// saslCall encodes remote_auth_sasl_start_args (string mechname, u_int nil,
// opaque data<>) and remote_auth_sasl_step_args (u_int nil, opaque data<>).
func saslCall(t *testing.T, conn net.Conn, proc, serial uint32, cred []byte) rawReply {
	t.Helper()
	var b []byte
	if proc == 68 { // SASL_START carries the mechanism name
		b = appendU32(b, uint32(len("PLAIN")))
		b = append(b, "PLAIN"...)
		b = append(b, 0, 0, 0) // mechname padding
	}
	b = appendU32(b, 0) // Nil
	b = appendU32(b, uint32(len(cred)))
	b = append(b, cred...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return saslRawCall(t, conn, 0x20008086, proc, serial, b)
}

func TestE2ESASLPlainChallenge(t *testing.T) {
	addr := startSASLServer(t)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	const program = 0x20008086

	// AUTH_LIST must advertise SASL.
	if r := saslRawCall(t, conn, program, 66, 1, nil); r.status != 0 {
		t.Fatalf("AUTH_LIST status = %d", r.status)
	}

	// Empty SASL_START → server challenges with "\0" (complete=0).
	resp := saslCall(t, conn, 68, 2, nil)
	if resp.status != 0 {
		t.Fatalf("SASL_START status = %d", resp.status)
	}
	if beU32(resp.payload) != 0 {
		t.Fatalf("expected challenge (complete=0), got %d", beU32(resp.payload))
	}
	chalLen := beU32(resp.payload[8:])
	if chalLen != 1 || resp.payload[12] != 0 {
		t.Fatalf("challenge payload = %v", resp.payload)
	}

	// SASL_STEP with credential: [authzid]\0[authcid]\0[passwd].
	cred := append([]byte{0}, "\x00sekrit-token"...)
	resp = saslCall(t, conn, 69, 3, cred)
	if resp.status != 0 {
		t.Fatalf("SASL_STEP status = %d payload=%q", resp.status, resp.payload)
	}
	if beU32(resp.payload) != 1 {
		t.Fatalf("SASL_STEP complete = %d", beU32(resp.payload))
	}

	// CONNECT_OPEN now succeeds.
	openPayload := []byte{1, 0, 0}
	openPayload = appendU32(openPayload, uint32(len("qemu:///system")))
	openPayload = append(openPayload, "qemu:///system"...)
	openPayload = appendU32(openPayload, 0)
	if r := saslRawCall(t, conn, program, 1, 4, openPayload); r.status != 0 {
		t.Fatalf("CONNECT_OPEN status = %d", r.status)
	}
	if r := saslRawCall(t, conn, 0x20009002, 0, 5, nil); r.status != 0 || r.program != 0x20009002 {
		t.Fatalf("KEEPALIVE reply = %+v", r)
	}
}

func TestE2ESASLPlainCredentialsInStart(t *testing.T) {
	addr := startSASLServer(t)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	cred := append([]byte{0}, "win-1\x00sekrit-token"...)
	resp := saslCall(t, conn, 68, 1, cred)
	if resp.status != 0 {
		t.Fatalf("SASL_START with creds status = %d", resp.status)
	}
	if beU32(resp.payload) != 1 {
		t.Fatalf("expected immediate completion, got %d", beU32(resp.payload))
	}

	// Hand the authenticated connection to the regular client: RPCs flow,
	// including NodeGetInfo whose Model is an opaque [32]int8.
	lv := l.New(conn)
	if err := lv.ConnectToURI("qemu:///system"); err != nil {
		t.Fatalf("ConnectToURI: %v", err)
	}
	defer lv.Disconnect()
	model, memory, cpus, _, _, _, _, _, err := lv.NodeGetInfo()
	if err != nil {
		t.Fatalf("NodeGetInfo: %v", err)
	}
	if cpus != 4 || memory == 0 {
		t.Fatalf("NodeGetInfo: cpus=%d memory=%d", cpus, memory)
	}
	if got := strings.TrimRight(int8sToString(model[:]), "\x00"); got != "x86_64" {
		t.Fatalf("model = %q", got)
	}
}

func TestE2ESASLPlainRejectsBadToken(t *testing.T) {
	addr := startSASLServer(t)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	cred := append([]byte{0}, "win-1\x00wrong"...)
	resp := saslCall(t, conn, 68, 1, cred)
	if resp.status == 0 {
		t.Fatal("expected SASL failure, got success")
	}
	// The error payload is a remote_error; the message must be uniform.
	if !strings.Contains(string(resp.payload), "authentication failed") {
		t.Fatalf("payload = %q", resp.payload)
	}
}
