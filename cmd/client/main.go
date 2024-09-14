// Package main is the entry point for the client application.
package main

import (
	"crypto/cipher"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Iam54r1n4/Gordafarid/core/crypto"
	"github.com/Iam54r1n4/Gordafarid/core/net/stream"
	"github.com/Iam54r1n4/Gordafarid/core/net/utils"
	"github.com/Iam54r1n4/Gordafarid/internal/config"
	"github.com/Iam54r1n4/Gordafarid/internal/logger"
	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

// Config represents the global configuration for the application.
var cfg *config.Config

// main is the entry point of the application.
// It loads configs, starts the client, and handles incoming connections.
func main() {
	// Load the config file
	var err error
	cfg, err = config.LoadConfig("./config.toml", config.ModeClient)
	if err != nil {
		logger.Fatal(errors.Join(proxy_error.ErrInvalidConfigFile, err))
	}

	// Initialize encryption algorithm
	aead, err := crypto.NewAEAD(cfg.Crypto.Algorithm, []byte(cfg.Crypto.Password))
	if err != nil {
		logger.Fatal(errors.Join(proxy_error.ErrCryptoInitFailed, err))
	}

	// Listen for incoming connections
	l, err := net.Listen("tcp", cfg.Client.Address)
	if err != nil {
		logger.Fatal(errors.Join(proxy_error.ErrClientListenFailed, err))
	}
	logger.Info("Client is listening on: ", cfg.Client.Address)

	// Accept & Handle incoming connections
	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Warn(errors.Join(proxy_error.ErrConnectionAccepting, err))
			continue
		}
		logger.Debug("Accepted connection from:", conn.RemoteAddr())
		go handleConnection(aead, conn)
	}
}

// handleConnection manages the connection between the client and the remote server.
// It establishes a connection to the remote server, sets up encryption, and handles
// bidirectional data transfer between the client and the server.
//
// Parameters:
//   - chacha: The cipher.AEAD instance for encryption/decryption
//   - c: The client connection
//
// Flow:
//  1. Establish connection to remote server
//  2. Set up encrypted stream
//  3. Start bidirectional data transfer
//  4. Handle and log any errors
func handleConnection(chacha cipher.AEAD, c net.Conn) {
	defer c.Close()

	// Dial remote server (normal tcp)
	rc, err := net.DialTimeout("tcp", cfg.Server.Address, time.Duration(cfg.DialTimeout)*time.Second)
	if err != nil {
		logger.Warn(errors.Join(proxy_error.ErrClientToServerDialFailed, err))
		return
	}
	// Convert incoming tcp connection into cipher stream (Read/Write methods are overridden)
	rc = stream.NewCipherStream(rc, chacha)
	defer rc.Close()

	// Initialize bidirectional data transferring
	wg := sync.WaitGroup{}
	wg.Add(2)
	errChan := make(chan error, 2)

	// Goroutine to copy data from client to remote
	go utils.DataTransfering(&wg, errChan, rc, c)
	// Goroutine to copy data from remote to client
	go utils.DataTransfering(&wg, errChan, c, rc)

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
