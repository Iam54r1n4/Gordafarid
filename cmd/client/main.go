// Package main is the entry point for the client application.
package main

import (
	"crypto/cipher"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/Iam54r1n4/Gordafarid/core/net/stream"
	"github.com/Iam54r1n4/Gordafarid/core/net/utils"
	"github.com/Iam54r1n4/Gordafarid/internal/logger"
	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

const (
	// laddr is the local address the client listens on.
	laddr = "127.0.0.1:8080"
	// raddr is the remote address the client connects to.
	raddr = "127.0.0.1:9090"
	// dialTimeout is the maximum time allowed for establishing a connection.
	dialTimeout = time.Second * 10

	// password is the encryption key used for the ChaCha20-Poly1305 cipher.
	password = "00000000000000000000000000000000"
)

// main is the entry point of the application.
// It starts the client, and handles incoming connections.
func main() {
	// Listen for incoming connections
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		logger.Fatal(errors.Join(proxy_error.ErrClientListenFailed, err))
	}
	logger.Info("Client is listening on: ", laddr)

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
		logger.Debug("Accepted connection from:", conn.RemoteAddr())
		go handleConnection(chacha, conn)
	}

}

// handleConnection manages the connection between the client and the remote server.
func handleConnection(chacha cipher.AEAD, c net.Conn) {
	defer c.Close()

	// Dial remote server (normal tcp)
	rc, err := net.DialTimeout("tcp", raddr, dialTimeout)
	if err != nil {
		logger.Warn(errors.Join(proxy_error.ErrClientToServerDialFailed, err))
		return
	}
	// Convert incoming tcp connection into cipher stream (Read/Write methods are overrided)
	rc = stream.NewCipherStream(rc, chacha)
	defer rc.Close()

	// Init bidirectional data transfering
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

	// Print the possible errors if there any
	for err := range errChan {
		// the EOF error is common for now
		if !errors.Is(err, io.EOF) {
			logger.Error(err)
		}
	}
}
