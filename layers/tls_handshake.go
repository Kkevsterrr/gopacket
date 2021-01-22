// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"fmt"
	"strings"

	"github.com/Kkevsterrr/gopacket"
	"golang.org/x/crypto/cryptobyte"
)

// TLS handshake message types.
const (
	typeClientHello uint8 = 1
)

// TLS extension numbers
const (
	extensionServerName uint16 = 0
)

// TLSHandshakeRecord defines the structure of a Handshare Record
type TLSHandshakeRecord struct {
	TLSRecordHeader

	HandshakeType uint8
	ClientHello   *TLSClientHello
}

type TLSClientHello struct {
	ServerName string
	Extensions []uint16
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSHandshakeRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	if t.Length == 0 {
		return nil // no payload to parse
	}

	if len(data) < 4 {
		return fmt.Errorf("tls: not enough bytes for handshake message")
	}
	t.HandshakeType = data[0] // may be encrypted
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) != 4+n {
		return nil // may be an encrypted handshake message
	}

	var m handshakeMessage
	switch t.HandshakeType {
	case typeClientHello:
		m = new(clientHelloMsg)
	}

	// The handshake message unmarshalers
	// expect to be able to keep references to data,
	// so pass in a fresh copy that won't be overwritten.
	data = append([]byte(nil), data...)

	if m != nil && !m.unmarshal(data) {
		return fmt.Errorf("tls: unable to unmarshal handshake message of type %d", t.HandshakeType)
	}

	// Attempt to decode client hello fields
	clientHello, ok := m.(*clientHelloMsg)
	if ok {
		t.ClientHello = &TLSClientHello{
			ServerName: clientHello.serverName,
			Extensions: clientHello.extensions,
		}
	}

	return nil
}

type handshakeMessage interface {
	unmarshal([]byte) bool
}

type clientHelloMsg struct {
	raw        []byte
	serverName string
	extensions []uint16
}

// Mostly copied from https://golang.org/src/crypto/tls/
func (m *clientHelloMsg) unmarshal(data []byte) bool {
	*m = clientHelloMsg{raw: data}
	s := cryptobyte.String(data)

	var tmp cryptobyte.String
	if !s.Skip(6) || // message type, uint24 length field, and uint16 version
		!s.Skip(32) || // random
		!s.ReadUint8LengthPrefixed(&tmp) || //sessionId
		!s.ReadUint16LengthPrefixed(&tmp) || // ciphersuites
		!s.ReadUint8LengthPrefixed(&tmp) { // compressionMethods
		return false
	}

	if s.Empty() {
		// ClientHello is optionally followed by extension data
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		m.extensions = append(m.extensions, extension)

		switch extension {
		case extensionServerName:
			// RFC 6066, Section 3
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return false
			}
			for !nameList.Empty() {
				var nameType uint8
				var serverName cryptobyte.String
				if !nameList.ReadUint8(&nameType) ||
					!nameList.ReadUint16LengthPrefixed(&serverName) ||
					serverName.Empty() {
					return false
				}
				if nameType != 0 {
					continue
				}
				if len(m.serverName) != 0 {
					// Multiple names of the same name_type are prohibited.
					return false
				}
				m.serverName = string(serverName)
				// An SNI value may not include a trailing dot.
				if strings.HasSuffix(m.serverName, ".") {
					return false
				}
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}
