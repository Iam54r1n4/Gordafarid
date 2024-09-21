// Package socks implements the SOCKS5 protocol for proxying TCP connections.
package socks

import (
	"context"
	"errors"
	"fmt"

	"github.com/Iam54r1n4/Gordafarid/pkg/net/utils"
)

// serverHandshake performs the SOCKS5 handshake process on the server side.
// It checks if the handshake is already complete, and if not, it handles the initial greeting and request.
//
// Parameters:
//   - ctx: The context for handling timeouts and cancellations.
//
// Returns:
//   - error: Any error encountered during the handshake process.
func (c *Conn) serverHandshake(ctx context.Context) error {
	if c.GetHandshakeComplete() {
		return nil
	}

	if err := c.serverHandleInitialGreeting(ctx); err != nil {
		return errors.Join(errFailedToHandleInitialGreeting, err)
	}

	if err := c.serverHandleRequest(ctx); err != nil {
		return errors.Join(errFailedToHandleRequest, err)
	}
	c.SetHandshakeComplete()

	return nil
}

// serverParseInitialGreetingHeaders reads and parses the initial SOCKS5 greeting headers from the client.
// It verifies the SOCKS version, reads the number of authentication methods, and the methods themselves.
//
// Parameters:
//   - ctx: The context for handling timeouts and cancellations.
//
// Returns:
//   - error: Any error encountered during parsing of the initial greeting headers.
func (c *Conn) serverParseInitialGreetingHeaders(ctx context.Context) error {
	// Read SOCKS version and number of methods
	buf := make([]byte, 2)
	if _, err := utils.ReadWithContext(ctx, c.Conn, buf); err != nil {
		c.greeting.methods = []byte{noAcceptableMethod}
		return errors.Join(errUnableToReadVersion, err)
	}

	// Verify SOCKS version
	if buf[0] != socks5Version {
		c.greeting.methods = []byte{noAcceptableMethod}
		return fmt.Errorf("%w: sent version: %d", errUnsupportedVersion, buf[0])
	}
	c.greeting.version = buf[0]

	// Verify number of methods
	nMethods := buf[1]
	if nMethods == 0 {
		c.greeting.methods = []byte{noAcceptableMethod}
		return fmt.Errorf("%w: sent nmethods: %d", errInvalidNMethodsValue, nMethods)
	}
	c.greeting.nMethods = buf[1]

	// Read authentication methods
	methods := make([]byte, nMethods)
	if _, err := utils.ReadWithContext(ctx, c.Conn, methods); err != nil {
		c.greeting.methods = []byte{noAcceptableMethod}
		return fmt.Errorf("%w: sent nmethods: %d, error: %v", errInvalidNMethodsValue, nMethods, err)
	}
	c.greeting.methods = methods
	return nil
}

// serverHandleInitialGreeting processes the initial SOCKS5 greeting from the client.
// It reads the client's supported authentication methods, selects the best method,
// and sends the method selection response back to the client.
//
// Parameters:
//   - ctx: The context for handling timeouts and cancellations.
//
// Returns:
//   - error: Any error encountered during handling of the initial greeting.
func (c *Conn) serverHandleInitialGreeting(ctx context.Context) error {

	if err := c.serverParseInitialGreetingHeaders(ctx); err != nil {
		return errors.Join(errFailedToParseInitialGreetingHeaders, err)
	}
	bestMethod, err := c.selectPreferredSocks5AuthMethod()
	if err != nil {
		return err
	}
	if err := c.verifyMethods(bestMethod); err != nil {
		if sendErr := c.serverSendMethodSelection(ctx, socks5Version, noAcceptableMethod); sendErr != nil {
			return errors.Join(errFailedToSendNoAcceptableMethodResponse, sendErr, err)
		}
		return errors.Join(errFailedToVerifyMethods, err)
	}
	if err := c.serverSendMethodSelection(ctx, socks5Version, bestMethod); err != nil {
		return errors.Join(errFailedToSendMethodSelectionResponse, err)
	}
	if bestMethod == userPassAuthMethod {
		if err := c.serverHandleUserPassAuthMethodNegotiation(ctx); err != nil {
			return errors.Join(errFailedToHandleUserPassAuthNegotiation, err)
		}
	}

	return nil
}

// serverParseRequestHeaders reads and parses the SOCKS5 request headers from the client.
// It verifies the SOCKS version, command, and reads the destination address and port.
//
// Parameters:
//   - ctx: The context for handling timeouts and cancellations.
//
// Returns:
//   - error: Any error encountered during parsing of the request headers.
func (c *Conn) serverParseRequestHeaders(ctx context.Context) error {
	// Read version, command, and reserved byte
	buf := make([]byte, 3)
	if _, err := utils.ReadWithContext(ctx, c.Conn, buf); err != nil {
		return errors.Join(errUnableToReadRequest, err)
	}
	if buf[0] != socks5Version || buf[1] != 1 {
		return fmt.Errorf("%w: unsupported socks request: Version: %d, Command: %d", errUnsupportedVersionOrCommand, buf[0], buf[1])
	}
	c.request.Version = buf[0]
	// TODO verify cmd and define const cmds
	c.request.Cmd = buf[1]
	c.request.rsv = buf[2]

	// Read address type
	if _, err := utils.ReadWithContext(ctx, c.Conn, buf[:1]); err != nil {
		return errors.Join(errUnableToReadAddressType, err)
	}
	c.request.Atyp = buf[0]

	var err error
	c.request.DstAddr, err = utils.ReadAddress(ctx, c.Conn, c.request.Atyp)
	if err != nil {
		return err
	}
	c.request.DstPort, err = utils.ReadPort(ctx, c.Conn)
	if err != nil {
		return err
	}
	return nil
}

// serverSendReplyResponse sends the SOCKS5 reply response back to the client.
// It sets the reply fields and writes the response to the connection.
//
// Parameters:
//   - ctx: The context for handling timeouts and cancellations.
//
// Returns:
//   - error: Any error encountered during sending of the reply response.
func (c *Conn) serverSendReplyResponse(ctx context.Context) error {
	c.reply.version = socks5Version
	c.reply.rep = 0
	c.reply.rsv = 0
	c.reply.Atyp = 1
	c.reply.DstAddr = []byte{0, 0, 0, 0}
	c.reply.DstPort = [2]byte{0, 0}
	if _, err := utils.WriteWithContext(ctx, c.Conn, c.reply.Bytes()); err != nil {
		return fmt.Errorf("%w: %v", errUnableToSendReplyResponse, err)
	}
	return nil
}

// serverHandleRequest processes the SOCKS5 request from the client.
// It parses the request headers and sends the reply response.
//
// Parameters:
//   - ctx: The context for handling timeouts and cancellations.
//
// Returns:
//   - error: Any error encountered during handling of the request.
func (c *Conn) serverHandleRequest(ctx context.Context) error {
	if err := c.serverParseRequestHeaders(ctx); err != nil {
		return errors.Join(errFailedToParseRequestHeaders, err)
	}
	if err := c.serverSendReplyResponse(ctx); err != nil {
		return errors.Join(errFailedToSendReplyResponse, err)
	}
	return nil
}

// serverSendTwoBytesResponse sends a two-byte response to the client.
// It is used for sending method selection and other simple responses.
//
// Parameters:
//   - ctx: The context for handling timeouts and cancellations.
//   - version: The SOCKS version byte to send.
//   - method: The method byte to send.
//
// Returns:
//   - error: Any error encountered during sending of the response.
func (c *Conn) serverSendTwoBytesResponse(ctx context.Context, version, method byte) error {
	_, err := utils.WriteWithContext(ctx, c.Conn, []byte{version, method})
	return err
}

// serverSendMethodSelection sends the method selection response to the client.
// It uses serverSendTwoBytesResponse to send the SOCKS version and selected authentication method.
//
// Parameters:
//   - ctx: The context for handling timeouts and cancellations.
//   - version: The SOCKS version byte to send.
//   - method: The selected authentication method byte to send.
//
// Returns:
//   - error: Any error encountered during sending of the method selection response.
func (c *Conn) serverSendMethodSelection(ctx context.Context, version, method byte) error {
	if err := c.serverSendTwoBytesResponse(ctx, version, method); err != nil {
		return fmt.Errorf("%w: %v", errUnableToSendMethodSelectionResponse, err)
	}
	return nil
}
