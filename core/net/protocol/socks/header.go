// Package socks implements the SOCKS protocol for network communication.
package socks

import (
	"github.com/Iam54r1n4/Gordafarid/core/net/protocol"
)

// greetingHeader represents the initial greeting message in the SOCKS protocol.
// It is used to establish the connection and negotiate authentication methods.
type greetingHeader struct {
	version  byte   // SOCKS protocol version (e.g., 0x05 for SOCKS5)
	nMethods byte   // Number of authentication methods supported by the client
	methods  []byte // List of supported authentication methods
}

// Size returns the total size of the greeting header in bytes.
// This is useful for allocating the correct amount of memory when serializing the header.
func (gh *greetingHeader) Size() int {
	return 1 + 1 + len(gh.methods) // 1 byte for version, 1 byte for nMethods, and the length of methods
}

// Bytes returns the greeting header as a byte slice.
// This method is used to serialize the header for network transmission.
func (gh *greetingHeader) Bytes() []byte {
	return append([]byte{gh.version, gh.nMethods}, gh.methods...)
}

// userPassAuthHeader represents the username/password authentication header.
// This is used when the server selects username/password authentication method.
type userPassAuthHeader struct {
	version  byte   // Subnegotiation version (typically 0x01)
	uLen     byte   // Username length (1-255 bytes)
	username []byte // Username
	pLen     byte   // Password length (1-255 bytes)
	password []byte // Password
}

// Size returns the total size of the username/password authentication header in bytes.
// This is useful for allocating the correct amount of memory when serializing the header.
func (upah *userPassAuthHeader) Size() int {
	return 1 + 1 + len(upah.username) + 1 + len(upah.password)
}

// Bytes returns the username/password authentication header as a byte slice.
// This method is used to serialize the header for network transmission.
func (ah *userPassAuthHeader) Bytes() []byte {
	res := make([]byte, 0, ah.Size())
	res = append(res, []byte{ah.version, ah.uLen}...)
	res = append(res, ah.username...)
	res = append(res, ah.pLen)
	res = append(res, ah.password...)
	return res
}

// requestHeader represents the SOCKS request header.
// This header is sent by the client to request the server to establish a connection or perform an operation.
type requestHeader struct {
	protocol.CommonHeader      // Embedded CommonHeader for shared fields
	rsv                   byte // Reserved byte, must be 0x00
}

// Size returns the total size of the request header in bytes.
// This is useful for allocating the correct amount of memory when serializing the header.
func (rh *requestHeader) Size() int {
	return 1 + rh.CommonHeader.Size() // 1 byte for rsv, plus the size of CommonHeader
}

// Bytes returns the request header as a byte slice.
// This method is used to serialize the header for network transmission.
func (rh *requestHeader) Bytes() []byte {
	res := make([]byte, 0, rh.Size())
	res = append(res, rh.CommonHeader.BasicHeader.Bytes()...)
	res = append(res, rh.rsv)
	res = append(res, rh.CommonHeader.AddressHeader.Bytes()...)
	return res
}

// replyHeader represents the SOCKS reply header.
// This header is sent by the server in response to a client's request.
type replyHeader struct {
	version                byte // SOCKS protocol version (e.g., 0x05 for SOCKS5)
	rep                    byte // Reply field indicating the status of the request
	rsv                    byte // Reserved byte, must be 0x00
	protocol.AddressHeader      // Embedded AddressHeader for server bound address
}

// Size returns the total size of the reply header in bytes.
// This is useful for allocating the correct amount of memory when serializing the header.
func (rh *replyHeader) Size() int {
	return 1 + 1 + 1 + rh.AddressHeader.Size() // 1 byte each for version, rep, rsv, plus AddressHeader size
}

// Bytes returns the reply header as a byte slice.
// This method is used to serialize the header for network transmission.
func (rh *replyHeader) Bytes() []byte {
	res := make([]byte, 0, rh.Size())
	res = append(res, rh.version, rh.rep, rh.rsv)
	res = append(res, rh.AddressHeader.Bytes()...)
	return res
}
