// Package gordafarid implements the Gordafarid protocol for secure communication.
package gordafarid

import "context"

/*
Gordafarid Handshake Process:

Client -> Server: Initial Greeting
+----+------------+
|VER | CMD | HASH |
+----+------------+
| 1  |  1  | 32   |
+----+------------+

VER: Gordafarid protocol version (0x01 for Gordafarid)
CMD: Command (0x01 for CONNECT, 0x02 for BIND, 0x03 for UDP ASSOCIATE)
HASH: Hash value used for authentication


Server -> Client: Greeting Response
+----+--------+
|VER | STATUS |
+----+--------+
| 1  |   1    |
+----+--------+

VER: Gordafarid protocol version (0x01 for Gordafarid)
STATUS: Status of the handshake (0x00 for success, 0x01 for failure)

***NOTICE***: After this stage all communication is encrypted.

Client -> Server: Request
+------+----------+----------+
| ATYP | DST.ADDR | DST.PORT |
+------+----------+----------+
|  1   | Variable |    2     |
+------+----------+----------+

ATYP: Address type (0x01 for IPv4, 0x03 for domain name, 0x04 for IPv6)
DST.ADDR: Destination address
DST.PORT: Destination port

Server -> Client: Reply

+----+--------+------+----------+----------+
|VER | STATUS | ATYP | BND.ADDR | BND.PORT |
+----+--------+------+----------+----------+
| 1  |   1    |  1   | Variable |    2     |
+----+--------+------+----------+----------+

VER: Gordafarid protocol version (0x01 for Gordafarid)
STATUS: Status of the handshake (0x00 for success, 0x01 for failure)
ATYP: Address type (0x01 for IPv4, 0x03 for domain name, 0x04 for IPv6)
BND.ADDR: Bound address
BND.PORT: Bound port
*/

// SetHandshakeComplete marks the handshake as complete for the connection.
// This method is used to indicate that the initial handshake process has finished successfully.
func (c *Conn) SetHandshakeComplete() {
	c.isHandshakeComplete.Store(true)
}

// GetHandshakeComplete returns the current handshake completion status.
// It returns true if the handshake has been completed, false otherwise.
func (c *Conn) GetHandshakeComplete() bool {
	return c.isHandshakeComplete.Load()
}

// Handshake initiates the handshake process for the connection.
// It uses a background context and delegates to HandshakeContext.
func (c *Conn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

// HandshakeContext performs the handshake process with a provided context.
// The context allows for cancellation and timeout control of the handshake operation.
func (c *Conn) HandshakeContext(ctx context.Context) error {
	return c.handshakeContext(ctx)
}

// handshakeContext is an internal method that implements the actual handshake logic.
// It checks if the handshake is already complete, and if not, executes the handshake function.
func (c *Conn) handshakeContext(ctx context.Context) error {
	if c.GetHandshakeComplete() {
		return nil // Handshake already completed, no need to perform it again
	}
	return c.handshakeFn(ctx) // Execute the handshake function with the provided context
}
