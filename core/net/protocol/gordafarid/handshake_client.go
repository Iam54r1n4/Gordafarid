package gordafarid

import (
	"context"
	"errors"

	"github.com/Iam54r1n4/Gordafarid/core/net/protocol/gordafarid/crypto"
	"github.com/Iam54r1n4/Gordafarid/core/net/utils"
)

// TODO: implement handshake timeout

// clientHandshake performs the client-side handshake process for establishing a secure connection.
// It follows a series of steps to authenticate and set up encryption with the server.
//
// The handshake process involves the following steps:
// 1. Send a greeting to the server
// 2. Handle the server's greeting response
// 3. Set up encryption using the agreed-upon algorithm
// 4. Send a request to the server
// 5. Mark the handshake as complete
//
// If the handshake is already complete, this function returns immediately.
//
// Parameters:
// - ctx: A context.Context for handling timeouts and cancellations
//
// Returns:
// - error: An error if any step of the handshake process fails, nil otherwise
func (c *Conn) clientHandshake(ctx context.Context) error {
	// Check if the handshake is already complete to avoid redundant operations
	if c.GetHandshakeComplete() {
		return nil
	}

	var err error

	// Step 1: Send the initial greeting to the server
	if err = c.clientSendGreeting(ctx); err != nil {
		return errors.Join(errClientFailedToSendInitialGreeting, err)
	}

	// Step 2: Handle the server's response to the greeting
	if err = c.clientHandleGreetingResponse(ctx); err != nil {
		return errors.Join(errClientFailedToHandleInitialGreetingResponse, err)
	}

	// Step 3: Set up encryption using the agreed-upon algorithm and the client's password
	aead, err := crypto.NewAEAD(c.config.encryptionAlgorithm, c.account.password)
	if err != nil {
		return errors.Join(errFailedToBuildAEADCipher, err)
	}

	// Wrap the existing connection with the newly created cipher for secure communication
	c.Conn = WrapConnToCipherConn(c.Conn, aead)

	// Step 4: Send the client's request to the server
	if err = c.clientSendRequest(ctx); err != nil {
		return errors.Join(errClientFailedToSendRequest, err)
	}

	// Step 5: Handle the server's response to the request
	if err = c.clientHandleReplyResponse(ctx); err != nil {
		return errors.Join(errClientFailedToHandleReplyResponse, err)
	}

	// Step 5: Mark the handshake as complete
	c.SetHandshakeComplete()

	return nil
}

// clientSendGreeting sends the initial greeting message from the client to the server.
// This is typically the first step in the handshake process.
//
// Parameters:
// - ctx: A context.Context for handling timeouts and cancellations
//
// Returns:
// - error: An error if the greeting couldn't be sent, nil otherwise
func (c *Conn) clientSendGreeting(ctx context.Context) error {
	_, err := utils.WriteWithContext(ctx, c.Conn, c.greeting.Bytes())
	return err
}

// clientSendRequest sends the client's request to the server after the initial handshake is complete.
// This typically includes authentication information or other protocol-specific data.
//
// Parameters:
// - ctx: A context.Context for handling timeouts and cancellations
//
// Returns:
// - error: An error if the request couldn't be sent, nil otherwise
func (c *Conn) clientSendRequest(ctx context.Context) error {
	_, err := utils.WriteWithContext(ctx, c.Conn, c.request.Bytes())
	return err
}

// clientHandleGreetingResponse processes the server's response to the client's initial greeting.
// This function verifies that the server supports the correct protocol version and that the greeting was successful.
//
// The response is expected to be a 2-byte array where:
// - The first byte represents the protocol version
// - The second byte indicates whether the greeting was successful or not
//
// Parameters:
// - ctx: A context.Context for handling timeouts and cancellations
//
// Returns:
// - error: An error if the response is invalid or indicates a failure, nil if the greeting was successful
func (c *Conn) clientHandleGreetingResponse(ctx context.Context) error {
	// Prepare a buffer to read the 2-byte response
	buf := make([]byte, 2)

	// Read the response from the server
	if _, err := utils.ReadWithContext(ctx, c.Conn, buf); err != nil {
		return err
	}

	// Check if the protocol version matches
	if buf[0] != gordafaridVersion {
		return errUnsupportedVersion
	}

	// Check if the greeting was successful
	if buf[1] == greetingFailed {
		return errGreetingFailed
	}

	return nil
}

func (c *Conn) clientHandleReplyResponse(ctx context.Context) error {
	var err error
	buf := make([]byte, 1)
	if _, err = utils.ReadWithContext(ctx, c.Conn, buf); err != nil {
		return err
	}
	if buf[0] != gordafaridVersion {
		return errUnsupportedVersion
	}
	c.reply.Version = buf[0]

	if _, err = utils.ReadWithContext(ctx, c.Conn, buf); err != nil {
		return err
	}
	if buf[0] != replySuccess {
		return errReplyFailed
	}

	if _, err = utils.ReadWithContext(ctx, c.Conn, buf); err != nil {
		return errors.Join(errUnableToReadAddressType, err)
	}
	c.reply.Bind.Atyp = buf[0]
	c.reply.Bind.DstAddr, err = utils.ReadAddress(ctx, c.Conn, c.reply.Bind.Atyp)
	if err != nil {
		return err
	}
	c.reply.Bind.DstPort, err = utils.ReadPort(ctx, c.Conn)

	return err
}
