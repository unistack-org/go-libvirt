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
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"github.com/unistack-org/go-libvirt/internal/constants"
)

// saslMechPlain is the only SASL mechanism the server advertises. PLAIN
// carries "[authzid]\0[authcid]\0[passwd]".
const saslMechPlain = "PLAIN"

// serverAuthState tracks SASL negotiation on one server connection.
type serverAuthState struct {
	mechRequested string
	complete      bool
	principal     Principal
}

// handleAuthList answers AUTH_LIST. The server advertises SASL (token
// auth) unless it is configured to allow unauthenticated dev connections.
func (c *serverConn) handleAuthList(_ *serverPacket, _ []byte) ([]byte, error) {
	types := []AuthType{constants.AuthSasl}
	if c.srv.AllowNoAuth {
		types = []AuthType{constants.AuthNone}
	}
	return serverEncodeArgs(&AuthListRet{Types: types})
}

// handleSaslInit answers AUTH_SASL_INIT: advertise PLAIN only.
func (c *serverConn) handleSaslInit(_ *serverPacket, _ []byte) ([]byte, error) {
	return serverEncodeArgs(&AuthSaslInitRet{Mechlist: saslMechPlain})
}

// handleSaslStart answers AUTH_SASL_START. With PLAIN the client normally
// sends the full credential immediately; if it sends no data the server
// issues the standard empty-realm challenge and expects the credential in
// a STEP.
func (c *serverConn) handleSaslStart(_ *serverPacket, payload []byte) ([]byte, error) {
	var args AuthSaslStartArgs
	if err := serverDecodeArgs(payload, &args); err != nil {
		return nil, err
	}
	if args.Mech != saslMechPlain {
		return nil, &serverRPCError{code: ErrOperationInvalid,
			msg: fmt.Sprintf("libvirt: server: unsupported SASL mechanism %q (only PLAIN)", args.Mech)}
	}
	c.auth.mechRequested = args.Mech
	data := int8ToBytes(args.Data)
	if len(data) == 0 {
		// Empty-realm PLAIN challenge ("\0").
		ret := AuthSaslStartRet{Complete: 0, Nil: 0, Data: bytesToInt8([]byte{0})}
		return serverEncodeArgs(&ret)
	}
	if err := c.completePlain(data); err != nil {
		return nil, err
	}
	ret := AuthSaslStartRet{Complete: 1, Nil: 0}
	return serverEncodeArgs(&ret)
}

// handleSaslStep answers AUTH_SASL_STEP (credential after the PLAIN
// challenge). PLAIN completes in one step.
func (c *serverConn) handleSaslStep(_ *serverPacket, payload []byte) ([]byte, error) {
	var args AuthSaslStepArgs
	if err := serverDecodeArgs(payload, &args); err != nil {
		return nil, err
	}
	if c.auth.mechRequested != saslMechPlain {
		return nil, &serverRPCError{code: ErrOperationInvalid, msg: "libvirt: server: SASL step without START"}
	}
	if err := c.completePlain(int8ToBytes(args.Data)); err != nil {
		return nil, err
	}
	ret := AuthSaslStepRet{Complete: 1, Nil: 0}
	return serverEncodeArgs(&ret)
}

// completePlain decodes the SASL PLAIN token
//
//	[authzid] "\0" [authcid] "\0" [passwd]
//
// and validates it against the configured TokenValidator.
func (c *serverConn) completePlain(data []byte) error {
	parts := bytes.SplitN(data, []byte{0}, 3)
	if len(parts) != 3 {
		return &serverRPCError{code: ErrAuthFailed, msg: "libvirt: server: malformed SASL PLAIN token"}
	}
	authzID, authcid, passwd := string(parts[0]), string(parts[1]), string(parts[2])

	if c.srv.TokenValidator == nil {
		return &serverRPCError{code: ErrAuthFailed, msg: "libvirt: server: no token validator configured"}
	}
	principal, err := c.srv.TokenValidator.Validate(authzID, authcid, passwd, c.sourceIP)
	if err != nil {
		// Never reveal why the credential failed.
		return &serverRPCError{code: ErrAuthFailed, msg: "libvirt: server: authentication failed"}
	}
	c.auth.complete = true
	c.auth.principal = principal
	c.srv.logf("libvirt: server: authenticated (authcid=%q) from %s", authcid, c.sourceIP)
	return nil
}

// HashToken is a helper for TokenValidator implementations: tokens are
// best stored hashed.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// CompareToken hashes got and constant-time compares it with want.
func CompareToken(want, got string) bool {
	return subtle.ConstantTimeCompare(HashToken(want), HashToken(got)) == 1
}
