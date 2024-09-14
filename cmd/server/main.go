// Package main is the entry point for the Gordafarid server application.
package main

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/Iam54r1n4/Gordafarid/core/net/socks"
	"github.com/Iam54r1n4/Gordafarid/core/net/stream"
	"github.com/Iam54r1n4/Gordafarid/core/net/utils"
	"github.com/Iam54r1n4/Gordafarid/internal/logger"
	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

const (
	// laddr is the local address on which the server listens.
	laddr = "127.0.0.1:9090"
	// dialTimeout is the maximum time allowed for establishing a connection to the target server.
	dialTimeout = time.Second * 10
	// handshakeTimeout is the maximum time allowed for completing the SOCKS5 handshake.
	handshakeTimeout = time.Second * 10

	// password is the encryption key used for the ChaCha20-Poly1305 cipher.
	password = "00000000000000000000000000000000"
)

// main is the entry point of the application.
// It starts the server, and handles incoming connections.
func main() {
	// Listen for incoming connections
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		logger.Fatal(errors.Join(proxy_error.ErrClientListenFailed, err))
	}
	logger.Info("Server is listening on: ", laddr)

	// Init crypto
	chacha, err := chacha20poly1305.New([]byte(password))
	if err != nil {
		logger.Fatal(errors.Join(proxy_error.ErrChacha20poly1305Failed, err))
	}

	// Accept & Handle incoming connections
	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Warn(errors.Join(proxy_error.ErrConnectionAccepting, err))
			continue
		}
		logger.Info("Accepted connection from:", conn.RemoteAddr())
		go handleConnection(context.Background(), chacha, conn)
	}
}

// handleConnection manages a single client connection.
// It performs the SOCKS5 handshake, establishes a connection to the target server,
// and facilitates bidirectional data transfer between the client and the target server.
func handleConnection(ctx context.Context, chacha cipher.AEAD, c net.Conn) {
	defer c.Close()
	// Convert incoming tcp connection into cipher stream (Read/Write methods are overrided)
	c = stream.NewCipherStream(c, chacha)

	// Perform socks5 handshake
	logger.Debug("Performing handshake...")
	hChan := make(chan socks.HandshakeChan)
	handshakeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	go socks.Handshake(handshakeCtx, c, hChan)

	// Wait for handshake result
	select {
	case <-handshakeCtx.Done():
		logger.Warn(proxy_error.ErrSocks5HandshakeTimeout)
	case hRes := <-hChan:
		// Check for handshake error
		if hRes.Err != nil {
			logger.Warn(errors.Join(proxy_error.ErrSocks5HandshakeFailed, hRes.Err))
			return
		}

		// Dial to target server
		fmt.Println("Handshake done")
		fmt.Println("Connecting to:", hRes.TAddr)
		tconn, err := net.DialTimeout("tcp", hRes.TAddr, dialTimeout)
		if err != nil {
			logger.Warn(errors.Join(proxy_error.ErrServerDialFailed, err))
			return
		}
		defer tconn.Close()

		// Log target server address
		if hRes.ATyp == socks.AtypDomain {
			logger.Debug(fmt.Sprintf("Connected to: %s(%s)", hRes.TAddr, tconn.RemoteAddr()))
		} else {
			logger.Debug("Connected to: ", tconn.RemoteAddr())
		}

		// Do realy proxying
		logger.Debug(fmt.Sprintf("Proxying between %s/%s", c.RemoteAddr(), tconn.RemoteAddr()))
		// Init bidirectional data transfering
		wg := sync.WaitGroup{}
		wg.Add(2)
		errChan := make(chan error, 2)

		// Goroutine to copy data from client to remote
		go utils.DataTransfering(&wg, errChan, tconn, c)
		// Goroutine to copy data from remote to client
		go utils.DataTransfering(&wg, errChan, c, tconn)

		// Close the errChan after the dataTransfering goroutines are finished
		go func() {
			wg.Wait()
			close(errChan)
		}()

		// Print the possible errors if there any
		for err := range errChan {
			// the EOF error is common for now
			if !errors.Is(err, io.EOF) {
				logger.Error(err)
			}
		}
		fmt.Println("----------------------------------------")
	}
}
