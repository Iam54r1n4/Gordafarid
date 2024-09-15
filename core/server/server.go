// Package server provides the main server functionality for the Gordafarid proxy.
package server

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
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

// Server represents the main server structure.
type Server struct {
	cfg      *config.Config // Configuration for the server
	aead     cipher.AEAD    // Authenticated Encryption with Associated Data for encryption
	listener net.Listener   // Network listener for incoming connections
}

// NewServer creates and returns a new Server instance.
//
// Example usage:
//
//		cfg := &config.Config{
//			Server: config.ServerConfig{
//				Address: "127.0.0.1:8080",
//			},
//			HandshakeTimeout: 10,
//			DialTimeout:      5,
//	        // ... other configuration fields
//		}
//		aead, _ := crypto.NewAEAD(cfg.Crypto.Algorithm, []byte(cfg.Crypto.Password))
//		server := NewServer(cfg, aead)
func NewServer(cfg *config.Config, aead cipher.AEAD) *Server {
	return &Server{
		cfg:  cfg,
		aead: aead,
	}
}

// Listen starts the server listening for incoming connections.
//
// Example usage:
//
//	err := server.Listen()
//	if err != nil {
//		log.Fatal("Failed to start server:", err)
//	}
func (s *Server) Listen() error {
	var err error
	s.listener, err = net.Listen("tcp", s.cfg.Server.Address)
	if err != nil {
		return err
	}
	logger.Info("Server is listening on: ", s.cfg.Server.Address)
	return nil
}

// Start begins accepting and handling incoming connections.
//
// Example usage:
//
//	err := server.Start()
//	if err != nil {
//		log.Fatal("Server error:", err)
//	}
func (s *Server) Start() error {
	if s.listener == nil {
		return proxy_error.ErrListenerIsNotInitialized
	}
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			logger.Warn(errors.Join(proxy_error.ErrConnectionAccepting, err))
			continue
		}
		logger.Info("Accepted connection from:", conn.RemoteAddr())
		go s.handleConnection(context.Background(), s.aead, conn)
	}
}

// handleConnection manages a single client connection.
// It performs the SOCKS5 handshake, establishes a connection to the target server,
// and facilitates bidirectional data transfer between the client and the target server.
//
// Parameters:
//   - ctx: The context for the connection
//   - aead: The cipher for encryption/decryption
//   - c: The client connection
//
// Example usage (internal to the Server.Start method):
//
//	go s.handleConnection(context.Background(), s.aead, conn)
func (s *Server) handleConnection(ctx context.Context, aead cipher.AEAD, c net.Conn) {
	defer c.Close()
	// Convert incoming TCP connection into cipher stream (Read/Write methods are overridden)
	c = stream.NewCipherStream(c, aead)

	// Perform SOCKS5 handshake
	logger.Debug("Performing handshake...")
	hChan := make(chan socks.HandshakeChan)
	handshakeCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.HandshakeTimeout)*time.Second)
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
		logger.Debug("Handshake done")
		logger.Debug("Connecting to:", hRes.TAddr)
		tconn, err := net.DialTimeout("tcp", hRes.TAddr, time.Duration(s.cfg.DialTimeout)*time.Second)
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

		// Perform relay proxying
		logger.Debug(fmt.Sprintf("Proxying between %s/%s", c.RemoteAddr(), tconn.RemoteAddr()))
		// Initialize bidirectional data transfer
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

		// Print the possible errors if there are any
		for err := range errChan {
			// The EOF error is common and expected
			if !errors.Is(err, io.EOF) {
				logger.Error(err)
			}
		}
	}
}
