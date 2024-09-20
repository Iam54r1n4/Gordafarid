package socks

import (
	"github.com/Iam54r1n4/Gordafarid/core/net/protocol"
)

// greetingHeader represents the initial greeting message in the SOCKS protocol
type greetingHeader struct {
	version  byte   // SOCKS protocol version
	nMethods byte   // Number of authentication methods supported
	methods  []byte // List of supported authentication methods
}

// Size returns the total size of the greeting header in bytes
func (gh *greetingHeader) Size() int {
	return 1 + 1 + len(gh.methods)
}

// Bytes returns the greeting header as a byte slice
func (gh *greetingHeader) Bytes() []byte {
	return append([]byte{gh.version, gh.nMethods}, gh.methods...)
}

// userPassAuthHeader represents the username/password authentication header
type userPassAuthHeader struct {
	version  byte   // Subnegotiation version
	uLen     byte   // Username length
	username []byte // Username
	pLen     byte   // Password length
	password []byte // Password
}

// Size returns the total size of the username/password authentication header in bytes
func (upah *userPassAuthHeader) Size() int {
	return 1 + 1 + len(upah.username) + 1 + len(upah.password)
}

// Bytes returns the username/password authentication header as a byte slice
func (ah *userPassAuthHeader) Bytes() []byte {
	res := make([]byte, 0, ah.Size())
	res = append(res, []byte{ah.version, ah.uLen}...)
	res = append(res, ah.username...)
	res = append(res, ah.pLen)
	res = append(res, ah.password...)
	return res
}

// requestHeader represents the SOCKS request header
type requestHeader struct {
	protocol.CommonHeader
	rsv byte // Reserved byte, must be 0x00
}

// Size returns the total size of the request header in bytes
func (rh *requestHeader) Size() int {
	return 1 + rh.CommonHeader.Size()
}

// Bytes returns the request header as a byte slice
func (rh *requestHeader) Bytes() []byte {
	res := make([]byte, 0, rh.Size())
	res = append(res, rh.CommonHeader.BasicHeaader.Bytes()...)
	res = append(res, rh.rsv)
	res = append(res, rh.CommonHeader.AddressHeader.Bytes()...)
	return res
}

// replyHeader represents the SOCKS reply header
type replyHeader struct {
	version                byte // SOCKS protocol version
	rep                    byte // Reply field
	rsv                    byte // Reserved byte, must be 0x00
	protocol.AddressHeader      // Embedded AddressHeader for server bound address
}

// Size returns the total size of the reply header in bytes
func (rh *replyHeader) Size() int {
	return 1 + 1 + 1 + rh.AddressHeader.Size()
}

// Bytes returns the reply header as a byte slice
func (rh *replyHeader) Bytes() []byte {
	res := make([]byte, 0, rh.Size())
	res = append(res, rh.version, rh.rep, rh.rsv)
	res = append(res, rh.AddressHeader.Bytes()...)
	return res
}
