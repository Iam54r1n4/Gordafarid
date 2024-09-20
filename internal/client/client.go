// Package client provides functionality for the client-side of the proxy.
package client

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/Iam54r1n4/Gordafarid/core/net/protocol"
	"github.com/Iam54r1n4/Gordafarid/core/net/protocol/gordafarid"
	"github.com/Iam54r1n4/Gordafarid/core/net/protocol/socks"
	"github.com/Iam54r1n4/Gordafarid/core/net/utils"
	"github.com/Iam54r1n4/Gordafarid/internal/config"
	"github.com/Iam54r1n4/Gordafarid/internal/flags"
	"github.com/Iam54r1n4/Gordafarid/internal/logger"
	"github.com/Iam54r1n4/Gordafarid/internal/shared_error"
)

// errUnableToGetSocks5HandshakeResult is an error returned when the SOCKS5 handshake result cannot be obtained.
var errUnableToGetSocks5HandshakeResult = errors.New("failed to get SOCKS5 handshake result")

// Client represents the client-side of the proxy.
type Client struct {
	cfg              *config.ClientConfig // Configuration for the client
	socks5Listener   *socks.Listener      // Socks5 listener for incoming connections
	gordafaridDialer *gordafarid.Dialer   // Gordafarid dialer for outgoing connections
}

// NewClient creates and returns a new Client instance.
//
// Parameters:
//   - cfg: A pointer to the client configuration.
//
// Returns:
//   - A pointer to the newly created Client instance.
//
// Example:
//
//	cfg := &config.Config{
//		Client: config.ClientConfig{
//			Address: "localhost:8080",
//		},
//		Server: config.ServerConfig{
//			Address: "example.com:9090",
//		},
//		DialTimeout: 30,
//	}
//	client := NewClient(cfg)
func NewClient(cfg *config.ClientConfig) *Client {
	return &Client{
		cfg: cfg,
	}
}

// Listen starts the client's TCP listener on the configured address.
//
// Returns:
//   - An error if the listener fails to start, nil otherwise.
//
// Example:
//
//	err := client.Listen()
//	if err != nil {
//		log.Fatal("Failed to start listener:", err)
//	}
func (c *Client) Listen() error {
	// Create a new SOCKS5 server configuration
	// Convert the credentials map to a ServerCredentials map
	var err error
	var socks5Credentials socks.ServerCredentials
	if c.cfg.Socks5Credentials != nil {
		socks5Credentials = make(socks.ServerCredentials)
		for u, p := range c.cfg.Socks5Credentials {
			socks5Credentials[u] = p
		}
	}
	socksConfig := socks.NewServerConfig(socks5Credentials, c.cfg.Timeout.Socks5HandshakeTimeout)

	// Create a new SOCKS5 listener with the specified address and configuration
	c.socks5Listener, err = socks.NewListener(c.cfg.Client.Address, socksConfig)
	if err != nil {
		return err
	}
	logger.Info("Client is listening for socks5 connections on: ", c.cfg.Client.Address)
	return nil
}

// Start begins accepting and handling incoming connections.
// This method runs indefinitely and should be called after Listen().
//
// Returns:
//   - An error if the listener is not initialized or if there's an error during execution.
func (c *Client) Start() error {
	if c.socks5Listener == nil {
		return shared_error.ErrListenerIsNotInitialized
	}

	// Create a Gordafarid dialer
	credential := gordafarid.NewCredential(c.cfg.Account.Username, c.cfg.Account.Password)
	accountConfig := gordafarid.NewDialAccountConfig(credential, flags.HashSaltFlag, c.cfg.CryptoAlgorithm)
	c.gordafaridDialer = gordafarid.NewDialer(accountConfig, nil)

	for {
		// Accept incoming SOCKS5 connections, the socks5 handshake will be performed automatically
		conn, err := c.socks5Listener.Accept()
		if err != nil {
			logger.Warn(errors.Join(shared_error.ErrConnectionAccepting, err))
			continue
		}
		logger.Debug("Accepted SOCKS5 connection from:", conn.RemoteAddr())

		// Create a context with a 1-hour timeout for each connection
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour*1)
		go func() {
			defer cancel() // Ensure the context is canceled when the goroutine exits
			c.handleConnection(ctx, conn)
		}()
	}
}

// handleConnection manages an individual client connection.
//
// Parameters:
//   - ctx: The context for the connection, used for cancellation and timeouts.
//   - conn: The SOCKS5 connection to handle.
func (c *Client) handleConnection(ctx context.Context, conn *socks.Conn) {
	defer conn.Close()

	// Get SOCKS5 handshake result
	handshakeResult, err := conn.GetHandshakeResult()
	if err != nil {
		logger.Error(errUnableToGetSocks5HandshakeResult, err)
		return
	}

	// Create dialer connection config
	dialerConnConfig := gordafarid.NewDialConnConfig(protocol.NewAddressHeader(handshakeResult.Atyp, handshakeResult.DstAddr, handshakeResult.DstPort))

	// Dial to remote server using Gordafarid protocol
	gordafaridHandshakeCtx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.Timeout.GordafaridHandshakeTimeout)*time.Second)
	defer cancel()
	grc, err := c.gordafaridDialer.DialContext(gordafaridHandshakeCtx, dialerConnConfig, c.cfg.Server.Address)
	if err != nil {
		logger.Warn(errors.Join(shared_error.ErrClientToServerDialFailed, err))
		return
	}
	// Initialize bidirectional data transferring
	wg := sync.WaitGroup{}
	wg.Add(2)
	errChan := make(chan error, 2)
	// Goroutine to copy data from client to remote
	go utils.DataTransfering(&wg, errChan, grc, conn)
	// Goroutine to copy data from remote to client
	go utils.DataTransfering(&wg, errChan, conn, grc)

	// Close the errChan after the dataTransfering goroutines are finished
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Print the possible errors if there are any
	for err := range errChan {
		// The EOF error is common and expected, so we ignore it
		if !errors.Is(err, io.EOF) {
			logger.Error(err)
		}
	}
}
