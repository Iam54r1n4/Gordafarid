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
// This function is responsible for handling a single SOCKS5 client connection.
// It performs the following steps:
// 1. Retrieves the SOCKS5 handshake result.
// 2. Creates a dialer connection configuration based on the handshake result.
// 3. Establishes a connection to the remote server using the Gordafarid protocol.
// 4. Initiates bidirectional data transfer between the client and the remote server.
// 5. Handles and logs any errors that occur during the process.
//
// The function uses goroutines to perform concurrent data transfer in both directions
// (client to remote and remote to client). It also utilizes a wait group and an error
// channel to manage these goroutines and collect any errors that may occur during
// the data transfer process.
//
// Parameters:
//   - ctx: context.Context - The context for the connection, used for cancellation and timeouts.
//   - conn: *socks.Conn - The SOCKS5 connection to handle.
//
// The function doesn't return any values, but it logs errors and manages the lifecycle
// of the connection, including closing it when the function exits.
//
// Error handling:
//   - If there's an error getting the SOCKS5 handshake result, it logs the error and returns.
//   - If there's an error dialing to the remote server, it logs the error and returns.
//   - Any errors during data transfer are logged, except for io.EOF which is expected and ignored.
//
// Concurrency:
// - The function uses goroutines and a WaitGroup to handle bidirectional data transfer concurrently.
// - It creates an error channel to collect errors from the data transfer goroutines.
// Note: This function is designed to be run as a goroutine for each incoming connection.
func (c *Client) handleConnection(ctx context.Context, conn *socks.Conn) {
	// Close the incoming SOCKS5(TCP) connection when the function returns
	defer conn.Close()

	// Get SOCKS5 handshake result from the SOCKS5 connection
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
