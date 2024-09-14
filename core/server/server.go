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

type Server struct {
	cfg      *config.Config
	aead     cipher.AEAD
	listener net.Listener
}

func NewServer(cfg *config.Config, aead cipher.AEAD) *Server {
	return &Server{
		cfg:  cfg,
		aead: aead,
	}
}

func (s *Server) Listen() error {
	// Listen for incoming connections
	var err error
	s.listener, err = net.Listen("tcp", s.cfg.Server.Address)
	if err != nil {
		return err
	}
	logger.Info("Server is listening on: ", s.cfg.Server.Address)
	return nil
}

func (s *Server) Start() error {
	// Accept and handle incoming connections
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
