package client

import (
	"crypto/cipher"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Iam54r1n4/Gordafarid/core/net/stream"
	"github.com/Iam54r1n4/Gordafarid/core/net/utils"
	"github.com/Iam54r1n4/Gordafarid/internal/config"
	"github.com/Iam54r1n4/Gordafarid/internal/logger"
	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

type Client struct {
	cfg      *config.Config
	aead     cipher.AEAD
	listener net.Listener
}

func NewClient(cfg *config.Config, aead cipher.AEAD) *Client {
	return &Client{
		cfg:  cfg,
		aead: aead,
	}
}

func (c *Client) Listen() error {
	// Listen for incoming connections
	var err error
	c.listener, err = net.Listen("tcp", c.cfg.Client.Address)
	if err != nil {
		return err
	}
	logger.Info("Client is listening on: ", c.cfg.Client.Address)
	return nil
}

func (c *Client) Start() error {
	// Accept & Handle incoming connections
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
//   - c: The client connection
//
// Flow:
//  1. Establish connection to remote server
//  2. Set up encrypted stream
//  3. Start bidirectional data transfer
//  4. Handle and log any errors
func (c *Client) handleConnection(aead cipher.AEAD, conn net.Conn) {
	defer conn.Close()

	// Dial remote server (normal tcp)
	rc, err := net.DialTimeout("tcp", c.cfg.Server.Address, time.Duration(c.cfg.DialTimeout)*time.Second)
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
	go utils.DataTransfering(&wg, errChan, rc, conn)
	// Goroutine to copy data from remote to client
	go utils.DataTransfering(&wg, errChan, conn, rc)

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
