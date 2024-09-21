package gordafarid

import (
	"context"
	"errors"

	"github.com/Iam54r1n4/Gordafarid/pkg/net/protocol"
	"github.com/Iam54r1n4/Gordafarid/pkg/net/protocol/gordafarid/crypto"

	"github.com/Iam54r1n4/Gordafarid/pkg/net/utils"
)

// serverHandshake performs the server-side handshake process for the Gordafarid protocol.
// It handles the initial greeting, authentication, and connection setup.
// This function is called when a new client connects to the server.
//
// Parameters:
// - ctx: The context for handling timeouts and cancellations.
//
// Returns:
// - error: Any error that occurred during the handshake process.
func (c *Conn) serverHandshake(ctx context.Context) error {
	// Check if the handshake is already complete to avoid redundant processing
	if c.GetHandshakeComplete() {
		return nil
	}

	var err error

	// Step 1: Handle the client's greeting
	if err = c.serverHandleGreeting(ctx); err != nil {
		// If greeting fails, send a failure message to the client
		if sendErr := c.serverSendGreetingFailed(ctx); sendErr != nil {
			return errors.Join(errServerFailedToSendGreetingFailedResponse, sendErr, err)
		}
		return errors.Join(errServerFailedToHandleInitialGreeting, err)
	}

	// Step 2: Send a success message for the greeting
	if err = c.serverSendGreetingSuccess(ctx); err != nil {
		return errors.Join(errServerFailedToSendGreetingSuccessResponse, err)
	}

	// Step 3: Set up encryption for the connection
	aead, err := crypto.NewAEAD(c.config.encryptionAlgorithm, c.account.password)
	if err != nil {
		return errors.Join(errFailedToBuildAEADCipher, err)
	}
	// Wrap the connection with the cipher for encrypted communication
	c.Conn = WrapConnToCipherConn(c.Conn, aead)

	// Step 4: Handle the client's request
	if err = c.handleRequest(ctx); err != nil {
		return errors.Join(errServerFailedToHandleRequest, err)
	}

	// Step 5: Send the server's reply to the client
	if err = c.serverSendReply(ctx); err != nil {
		return errors.Join(errServerFailedToSendReplyResponse, err)
	}

	return nil
}

// serverHandleGreeting processes the initial greeting from the client.
// It reads and validates the protocol version, command, and account hash.
// This function also performs authentication based on the received information.
//
// Parameters:
// - ctx: The context for handling timeouts and cancellations.
//
// Returns:
// - error: Any error that occurred during the greeting process.
func (c *Conn) serverHandleGreeting(ctx context.Context) error {
	// Step 1: Read and validate the protocol version
	buf := make([]byte, 1)
	var err error
	if _, err = utils.ReadWithContext(ctx, c.Conn, buf); err != nil {
		return errors.Join(errUnableToReadVersion, err)
	}
	if buf[0] != gordafaridVersion {
		return errUnsupportedVersion
	}
	c.greeting.Version = buf[0]

	// Step 2: Read and validate the command
	buf = make([]byte, 1)
	if _, err = utils.ReadWithContext(ctx, c.Conn, buf); err != nil {
		return errors.Join(errUnableToReadCmd, err)
	}
	if buf[0] != protocol.CmdConnect {
		return errUnsupportedCmd
	}
	c.greeting.Cmd = buf[0]

	// Step 3: Read and validate the account hash
	buf = make([]byte, HashSize)
	n, err := utils.ReadWithContext(ctx, c.Conn, buf)
	if err != nil {
		return errors.Join(errUnableToReadAccountHash, err)
	}
	if n < HashSize {
		return errInvalidAccountHash
	}
	copy(c.greeting.hash[:], buf)

	// Step 4: Perform authentication
	if err = c.handleAuthentication(); err != nil {
		return err
	}

	// Mark the handshake as complete
	c.SetHandshakeComplete()
	return nil
}

// handleRequest processes the client's request after the initial handshake.
// It reads the address type, destination address, and destination port.
//
// Parameters:
// - ctx: The context for handling timeouts and cancellations.
//
// Returns:
// - error: Any error that occurred during the request handling process.
func (c *Conn) handleRequest(ctx context.Context) error {
	var err error
	buf := make([]byte, 1)

	// Step 1: Read the address type
	if _, err = utils.ReadWithContext(ctx, c.Conn, buf); err != nil {
		return errors.Join(errUnableToReadAddressType, err)
	}
	c.request.Atyp = buf[0]

	// Step 2: Read the destination address
	c.request.DstAddr, err = utils.ReadAddress(ctx, c.Conn, c.request.Atyp)
	if err != nil {
		return err
	}

	// Step 3: Read the destination port
	c.request.DstPort, err = utils.ReadPort(ctx, c.Conn)
	if err != nil {
		return err
	}

	return nil
}

// buildReplyResponse constructs the reply message to be sent back to the client.
// It sets the protocol version, status, and copies the request details into the reply.
//
// Returns:
// - error: Any error that occurred during the reply construction process.
func (c *Conn) buildReplyResponse() error {
	c.reply.Version = gordafaridVersion
	c.reply.Status = replySuccess
	c.reply.Bind.Atyp = c.request.Atyp
	c.reply.Bind.DstAddr = c.request.DstAddr
	c.reply.Bind.DstPort = c.request.DstPort
	return nil
}

// serverSendReply sends the constructed reply back to the client.
// It first builds the reply response and then writes it to the connection.
//
// Parameters:
// - ctx: The context for handling timeouts and cancellations.
//
// Returns:
// - error: Any error that occurred during the reply sending process.
func (c *Conn) serverSendReply(ctx context.Context) error {
	var err error
	if err = c.buildReplyResponse(); err != nil {
		return err
	}
	if _, err = utils.WriteWithContext(ctx, c.Conn, c.reply.Bytes()); err != nil {
		return err
	}
	return nil
}

// serverSendGreetingSuccess sends a success message to the client after the greeting phase.
// It uses the sendTwoBytesResponse helper function to send the protocol version and success status.
//
// Parameters:
// - ctx: The context for handling timeouts and cancellations.
//
// Returns:
// - error: Any error that occurred during the success message sending process.
func (c *Conn) serverSendGreetingSuccess(ctx context.Context) error {
	return c.sendTwoBytesResponse(ctx, gordafaridVersion, greetingSuccess)
}

// serverSendGreetingFailed sends a failure message to the client if the greeting phase fails.
// It uses the sendTwoBytesResponse helper function to send the protocol version and failure status.
//
// Parameters:
// - ctx: The context for handling timeouts and cancellations.
//
// Returns:
// - error: Any error that occurred during the failure message sending process.
func (c *Conn) serverSendGreetingFailed(ctx context.Context) error {
	return c.sendTwoBytesResponse(ctx, gordafaridVersion, greetingFailed)
}