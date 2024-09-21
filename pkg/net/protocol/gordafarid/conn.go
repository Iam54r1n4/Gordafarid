package gordafarid

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/Iam54r1n4/Gordafarid/pkg/net/protocol"
	"github.com/Iam54r1n4/Gordafarid/pkg/net/utils"
)

// handshakeFunction is a type definition for a function that performs
// the handshake process. It takes a context and returns an error if
// the handshake fails.
type handshakeFunction func(ctx context.Context) error

// account represents user authentication information.
type account struct {
	hash     Hash   // Hash of the account, used for identification
	password []byte // Password associated with the account
}

// Conn represents a connection using the Gordafarid protocol.
// It wraps a standard net.Conn and adds protocol-specific functionality.
type Conn struct {
	net.Conn         // Embedded net.Conn for underlying network operations
	config   *Config // Configuration
	account  account // Account information for authentication

	// Headers used in the protocol
	greeting greetingHeader // Greeting header for initial communication
	request  requestHeader  // Request header for client requests
	reply    replyHeader    // Reply header for server responses

	handshakeFn         handshakeFunction // Function to perform the handshake
	isHandshakeComplete atomic.Bool       // Flag to track if handshake is complete
	isClient            bool              // Indicates whether this is a client connection
}

// Read reads data from the connection.
// It ensures that the handshake is complete before reading.
func (c *Conn) Read(b []byte) (int, error) {
	// Check if handshake is complete
	if !c.GetHandshakeComplete() {
		// If not, perform the handshake
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}
	// Proceed with reading from the underlying connection
	return c.Conn.Read(b)
}

// Write writes data to the connection.
// It ensures that the handshake is complete before writing.
func (c *Conn) Write(b []byte) (int, error) {
	// Check if handshake is complete
	if !c.GetHandshakeComplete() {
		// If not, perform the handshake
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}
	// Proceed with writing to the underlying connection
	return c.Conn.Write(b)
}

// sendTwoBytesResponse sends a two-byte response to the other end of the connection.
// This is typically used for sending version and status information.
func (c *Conn) sendTwoBytesResponse(ctx context.Context, version, status byte) error {
	// Write the version and status bytes to the connection
	if _, err := utils.WriteWithContext(ctx, c.Conn, []byte{version, status}); err != nil {
		return err
	}
	return nil
}

// GetHandshakeResult returns the address header from the request after ensuring
// that the handshake is complete. This is useful for obtaining information about
// the client's requested destination.
func (c *Conn) GetHandshakeResult() (protocol.AddressHeader, error) {
	// Check if handshake is complete
	if !c.GetHandshakeComplete() {
		// If not, perform the handshake
		if err := c.Handshake(); err != nil {
			return protocol.AddressHeader{}, err
		}
	}
	// Return the address header from the request
	return c.request.AddressHeader, nil
}
