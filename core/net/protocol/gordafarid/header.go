// Package gordafarid implements the Gordafarid protocol, a custom network protocol for secure communication.
package gordafarid

import "github.com/Iam54r1n4/Gordafarid/core/net/protocol"

// greetingHeader represents the header structure for the greeting message in the Gordafarid protocol.
type greetingHeader struct {
	protocol.BasicHeader                // Embedded BasicHeader from the protocol package
	hash                 [HashSize]byte // Hash value used for authentication or integrity checking
}

// Size returns the total size of the greeting header in bytes.
func (gh *greetingHeader) Size() int {
	return gh.BasicHeader.Size() + HashSize
}

// Bytes serializes the greeting header into a byte slice.
func (gh *greetingHeader) Bytes() []byte {
	return append(gh.BasicHeader.Bytes(), gh.hash[:]...)
}

// requestHeader represents the header structure for request messages in the Gordafarid protocol.
type requestHeader struct {
	protocol.AddressHeader // Embedded AddressHeader from the protocol package
}

// Size returns the total size of the request header in bytes.
func (rh *requestHeader) Size() int {
	return rh.AddressHeader.Size()
}

// Bytes serializes the request header into a byte slice.
func (rh *requestHeader) Bytes() []byte {
	return rh.AddressHeader.Bytes()
}

// replyHeader represents the header structure for reply messages in the Gordafarid protocol.
type replyHeader struct {
	Version byte                   // Protocol version
	Status  byte                   // Status code of the reply
	Bind    protocol.AddressHeader // Address information for binding
}

// Size returns the total size of the reply header in bytes.
func (rh *replyHeader) Size() int {
	return 1 + 1 + rh.Bind.Size() // 1 byte for Version, 1 byte for Status, plus the size of the AddressHeader
}

// Bytes serializes the reply header into a byte slice.
func (rh *replyHeader) Bytes() []byte {
	return append([]byte{rh.Version, rh.Status}, rh.Bind.Bytes()...)
}
