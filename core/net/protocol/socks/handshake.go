package socks

import (
	"context"
)

// Handshake performs the SOCKS5 handshake process
// This function follows the SOCKS5 protocol as defined in RFC 1928 and RFC 1929
// https://www.ietf.org/rfc/rfc1928.txt
// https://www.ietf.org/rfc/rfc1929.txt
// It handles the initial greeting, method selection, authentication (if required), and the SOCKS5 request

// Client -> Server: Initial Greeting
// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+

// Server -> Client: Method Selection
// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+

// If USERNAME/PASSWORD authentication is selected:
// Client -> Server: Username/Password Authentication
// +----+------+----------+------+----------+
// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
// +----+------+----------+------+----------+
// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
// +----+------+----------+------+----------+

// Server -> Client: Authentication Response
// +----+--------+
// |VER | STATUS |
// +----+--------+
// | 1  |   1    |
// +----+--------+

// Client -> Server: SOCKS5 Request
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+

// Server -> Client: SOCKS5 Reply
// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+

// VER: SOCKS version (0x05 for SOCKS5)
// NMETHODS: Number of authentication methods supported
// METHODS: Authentication methods supported
// CMD: Command (0x01 for CONNECT, 0x02 for BIND, 0x03 for UDP ASSOCIATE)
// RSV: Reserved byte, must be 0x00
// ATYP: Address type (0x01 for IPv4, 0x03 for Domain, 0x04 for IPv6)
// DST.ADDR: Destination address
// DST.PORT: Destination port
// REP: Reply field (0x00 for success, other values for various errors)
// BND.ADDR: Server bound address
// BND.PORT: Server bound port
// ULEN: Username length
// UNAME: Username
// PLEN: Password length
// PASSWD: Password
// STATUS: Authentication status (0x00 for success, 0x01 for failure)

// Handshake initiates the SOCKS handshake process.
// It's a convenience method that calls HandshakeContext with a background context.
func (c *Conn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

// HandshakeContext initiates the SOCKS handshake process with a given context.
// The context allows for cancellation and timeout control of the handshake process.
func (c *Conn) HandshakeContext(ctx context.Context) error {
	return c.handshakeContext(ctx)
}

// handshakeContext is the internal method that performs the actual SOCKS handshake.
// It checks if the handshake has already been completed, and if not, it calls the handshake function.
func (c *Conn) handshakeContext(ctx context.Context) error {
	// If the handshake is already complete, return immediately
	if c.GetHandshakeComplete() {
		return nil
	}
	// Perform the handshake using the stored handshake function
	return c.handshakeFn(ctx)
}

// SetHandshakeComplete marks the handshake as complete.
// This method is used to indicate that the SOCKS handshake process has finished successfully.
func (c *Conn) SetHandshakeComplete() {
	c.isHandshakeComplete.Store(true)
}

// GetHandshakeComplete returns the current handshake completion status.
// It returns true if the handshake has been completed, false otherwise.
func (c *Conn) GetHandshakeComplete() bool {
	return c.isHandshakeComplete.Load()
}
