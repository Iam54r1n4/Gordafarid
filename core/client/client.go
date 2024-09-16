// Package client provides functionality for the client-side of the proxy.
package client

import (
	"crypto/cipher"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Iam54r1n4/Gordafarid/core/net/socks"
	"github.com/Iam54r1n4/Gordafarid/core/net/stream"
	"github.com/Iam54r1n4/Gordafarid/core/net/utils"
	"github.com/Iam54r1n4/Gordafarid/internal/config"
	"github.com/Iam54r1n4/Gordafarid/internal/logger"
	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

// Client represents the client-side of the proxy.
type Client struct {
	cfg      *config.Config // Configuration for the client
	aead     cipher.AEAD    // Authenticated Encryption with Associated Data for encryption
	listener net.Listener   // TCP listener for incoming connections
}

// NewClient creates and returns a new Client instance.
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
//	aead, _ := cipher.NewGCM(block)
//	client := NewClient(cfg, aead)
func NewClient(cfg *config.Config, aead cipher.AEAD) *Client {
	return &Client{
		cfg:  cfg,
		aead: aead,
	}
}

// Listen starts the client's TCP listener on the configured address.
//
// Example:
//
//	err := client.Listen()
//	if err != nil {
//		log.Fatal("Failed to start listener:", err)
//	}
func (c *Client) Listen() error {
	var err error
	c.listener, err = net.Listen("tcp", c.cfg.Client.Address)
	if err != nil {
		return err
	}
	logger.Info("Client is listening on: ", c.cfg.Client.Address)
	return nil
}

// Start begins accepting and handling incoming connections.
// This method runs indefinitely and should be called after Listen().
func (c *Client) Start() error {
	if c.listener == nil {
		return proxy_error.ErrListenerIsNotInitialized
	}
	for {
		conn, err := c.listener.Accept()
		if err != nil {
			logger.Warn(errors.Join(proxy_error.ErrConnectionAccepting, err))
			continue
		}
		logger.Debug("Accepted connection from:", conn.RemoteAddr())
		go c.handleConnection(c.aead, conn)
	}
}

// handleConnection manages the connection between the client and the remote server.
// It establishes a connection to the remote server, sets up encryption, and handles
// bidirectional data transfer between the client and the server.
//
// Parameters:
//   - aead: The cipher.AEAD instance for encryption/decryption
//   - conn: The client connection
//
// Flow:
//  1. Establish connection to remote server
//  2. Set up encrypted stream
//  3. Start bidirectional data transfer
//  4. Handle and log any errors
//
// This method is typically called as a goroutine for each new connection.
//
// Example:
//
//	conn, _ := net.Dial("tcp", "localhost:8080")
//	go client.handleConnection(aead, conn)
func (c *Client) handleConnection(aead cipher.AEAD, conn net.Conn) {
	defer conn.Close()

	// Store a copy of connection data (to avoid consuming the connection on the client side)
	// This allows us to read and validate the SOCKS5 initial greeting without consuming the connection
	bufconn := utils.NewBufferedConn(conn)
	// Start buffering the connection with a maximum size of MaxInitialGreetingSize
	bufconn.StartBuffering(socks.MaxInitialGreetingSize)

	// Validate the SOCKS5 request
	// This step ensures that the incoming connection follows the SOCKS5 protocol
	if err := socks.ValidateSocks5(c.cfg.Timeout.Socks5ValidationTimeout, bufconn); err != nil {
		// If validation fails, log a warning with the error details and return from the function
		logger.Warn(errors.Join(proxy_error.ErrSocks5HeaderValidationFailed, err))
		return
	}

	// Reset the buffer to its initial state, allowing us to read the data again
	bufconn.Backtrack()
	// Stop buffering as we no longer need to preserve the initial data
	bufconn.StopBuffering()

	// Dial remote server (normal tcp)
	rc, err := net.DialTimeout("tcp", c.cfg.Server.Address, time.Duration(c.cfg.Timeout.DialTimeout)*time.Second)
	if err != nil {
		logger.Warn(errors.Join(proxy_error.ErrClientToServerDialFailed, err))
		return
	}
	// Convert incoming tcp connection into cipher stream (Read/Write methods are overridden)
	rc = stream.NewCipherStream(rc, aead)
	defer rc.Close()

	// Initialize bidirectional data transferring
	wg := sync.WaitGroup{}
	wg.Add(2)
	errChan := make(chan error, 2)

	// Goroutine to copy data from client to remote
	go utils.DataTransfering(&wg, errChan, rc, bufconn)
	// Goroutine to copy data from remote to client
	go utils.DataTransfering(&wg, errChan, bufconn, rc)

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
