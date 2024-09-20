// Package server provides the main server functionality for the Gordafarid proxy.
package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Iam54r1n4/Gordafarid/core/net/protocol"
	"github.com/Iam54r1n4/Gordafarid/core/net/protocol/gordafarid"
	"github.com/Iam54r1n4/Gordafarid/core/net/utils"
	"github.com/Iam54r1n4/Gordafarid/internal/config"
	"github.com/Iam54r1n4/Gordafarid/internal/flags"
	"github.com/Iam54r1n4/Gordafarid/internal/logger"
	"github.com/Iam54r1n4/Gordafarid/internal/shared_error"
)

var errUnableToGetGordafaridHandshakeResult = errors.New("failed to get Gordafarid handshake result")

// Server represents the main server structure.
type Server struct {
	cfg                *config.ServerConfig // Configuration for the server
	gordafaridListener *gordafarid.Listener // Network listener for incoming connections
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
func NewServer(cfg *config.ServerConfig) *Server {
	return &Server{
		cfg: cfg,
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

	var gordafaridCredentials []gordafarid.Credential

	if s.cfg.Credentials != nil {
		for _, account := range s.cfg.Credentials {
			gordafaridCredentials = append(gordafaridCredentials, gordafarid.NewCredential(account.Username, account.Password))
		}
	}

	listenConfig := gordafarid.NewServerConfig(gordafaridCredentials, flags.HashSaltFlag, s.cfg.CryptoAlgorithm, s.cfg.Timeout.GordafaridHandshakeTimeout)
	s.gordafaridListener, err = gordafarid.Listen(s.cfg.Server.Address, listenConfig)
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
	if s.gordafaridListener == nil {
		return shared_error.ErrListenerIsNotInitialized
	}
	for {
		conn, err := s.gordafaridListener.Accept()
		if err != nil {
			logger.Warn(errors.Join(shared_error.ErrConnectionAccepting, err))
			continue
		}
		logger.Info("Accepted connection from:", conn.RemoteAddr())
		//ctx, _ := context.WithTimeout(context.Background(), time.Hour*1)
		go s.handleConnection(conn)
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
func (s *Server) handleConnection(gc *gordafarid.Conn) {
	defer gc.Close()

	handshakeResult, err := gc.GetHandshakeResult()
	if err != nil {
		logger.Warn(errors.Join(errUnableToGetGordafaridHandshakeResult, err))
		return
	}

	// Target info
	dstAddr := string(handshakeResult.DstAddr)
	dstPort := binary.BigEndian.Uint16(handshakeResult.DstPort[:])
	targetAddr := net.JoinHostPort(dstAddr, fmt.Sprint(dstPort))
	// Dial to target server
	logger.Debug("Handshake done")
	logger.Debug("Connecting to:", dstAddr)
	tconn, err := net.DialTimeout("tcp", targetAddr, time.Duration(s.cfg.Timeout.DialTimeout)*time.Second)
	if err != nil {
		logger.Warn(errors.Join(shared_error.ErrServerDialFailed, err))
		return
	}
	defer tconn.Close()

	// Log target server address
	if handshakeResult.Atyp == protocol.AtypDomain {
		logger.Debug(fmt.Sprintf("Connected to: %s(%s)", dstAddr, tconn.RemoteAddr()))
	} else {
		logger.Debug("Connected to: ", tconn.RemoteAddr())
	}

	// Perform relay proxying
	logger.Debug(fmt.Sprintf("Proxying between %s/%s", gc.RemoteAddr(), tconn.RemoteAddr()))

	// x := []byte("i will fuck you")
	// gc.Write(x)
	// logger.Warn("x writeen")

	// y := make([]byte, 15)
	// gc.Read(y)
	// logger.Warn("the y received in bytes:", y)
	// logger.Warn("the y received in string:", string(y))

	// Initialize bidirectional data transfer
	wg := sync.WaitGroup{}
	wg.Add(2)
	errChan := make(chan error, 2)

	// Goroutine to copy data from client to remote
	go utils.DataTransfering(&wg, errChan, tconn, gc)
	// Goroutine to copy data from remote to client
	go utils.DataTransfering(&wg, errChan, gc, tconn)

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
