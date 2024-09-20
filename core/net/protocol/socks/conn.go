// Package socks implements the SOCKS protocol for network connections.
package socks

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/Iam54r1n4/Gordafarid/core/net/protocol"
)

// handshakeFunction is a type that represents a function to perform a handshake.
type handshakeFunction func(ctx context.Context) error

// Conn represents a SOCKS connection.
// Conn represents a SOCKS connection.
type Conn struct {
	// Embed the standard net.Conn interface to inherit its methods
	net.Conn

	// serverConfig holds the configuration for the SOCKS server
	serverConfig *ServerConfig

	// Headers used in the SOCKS protocol
	greeting     greetingHeader     // Stores the initial greeting message from the client
	request      requestHeader      // Stores the client's connection request details
	reply        replyHeader        // Stores the server's reply to the client's request
	userPassAuth userPassAuthHeader // Stores username/password authentication details

	// handshakeFn is a function that performs the SOCKS handshake
	handshakeFn handshakeFunction

	// isHandshakeComplete is an atomic boolean indicating whether the handshake is finished
	isHandshakeComplete atomic.Bool

	// isClient indicates whether this Conn is operating in client mode (true) or server mode (false)
	isClient bool
}

// Read reads data from the connection.
// If the handshake is not complete, it performs the handshake before reading.
func (c *Conn) Read(b []byte) (int, error) {
	if !c.GetHandshakeComplete() {
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

// Write writes data to the connection.
// If the handshake is not complete, it performs the handshake before writing.
func (c *Conn) Write(b []byte) (int, error) {
	if !c.GetHandshakeComplete() {
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(b)
}

// GetHandshakeResult returns the address header from the request after completing the handshake.
// If the handshake is not complete, it performs the handshake before returning the result.
func (c *Conn) GetHandshakeResult() (protocol.AddressHeader, error) {
	if !c.GetHandshakeComplete() {
		if err := c.Handshake(); err != nil {
			return protocol.AddressHeader{}, err
		}
	}
	return c.request.AddressHeader, nil
}
