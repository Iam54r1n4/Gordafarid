// Package gordafarid implements the Gordafarid protocol for secure communication.
package gordafarid

import "context"

// TODO: draw a diagram of the handshake process

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
