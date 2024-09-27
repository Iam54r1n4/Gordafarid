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

	"github.com/Iam54r1n4/Gordafarid/internal/config"
	"github.com/Iam54r1n4/Gordafarid/internal/logger"
	"github.com/Iam54r1n4/Gordafarid/internal/shared_error"
	"github.com/Iam54r1n4/Gordafarid/pkg/net/protocol"
	"github.com/Iam54r1n4/Gordafarid/pkg/net/protocol/gordafarid"
	"github.com/Iam54r1n4/Gordafarid/pkg/net/utils"
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

	listenConfig := gordafarid.NewServerConfig(gordafaridCredentials, s.cfg.CryptoAlgorithm, s.cfg.Server.InitPassword, s.cfg.Timeout.GordafaridHandshakeTimeout)
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

	acceptedConnChan := make(chan *gordafarid.Conn, 64)
	errChan := make(chan error, 64)
	defer close(acceptedConnChan)
	defer close(errChan)

	go func() {
		for {
			conn, err := s.gordafaridListener.Accept()
			if err != nil {
				select {
				case errChan <- err:
				default:
					logger.Warn("Error channel is full, dropping error:", err)
				}
				// Skip the rest of the loop iteration if there's an error
				continue
			}
			if conn == nil {
				logger.Warn("Accepted a nil connection, WTF?!")
				continue
			}

			select {
			case acceptedConnChan <- conn:
			default:
				logger.Warn("Connection channel is full, dropping connection from:", conn.RemoteAddr())
				conn.Close() // Optionally close the connection if the buffer is full
			}
		}
	}()

	for {
		select {
		case conn := <-acceptedConnChan:
			// Ensure conn is not nil before accessing its methods
			if conn == nil {
				logger.Warn("Received nil connection from channel, WTF?!")
				continue
			}

			logger.Info("Accepted connection from:", conn.RemoteAddr())
			go s.handleConnection(conn)
		case err := <-errChan:
			logger.Warn(errors.Join(shared_error.ErrConnectionAccepting, err))
		}
	}
}

// handleConnection manages a single client connection.
// It performs the Gordafarid handshake, establishes a connection to the target server,
// and facilitates bidirectional data transfer between the client and the target server.
//
// This function is the core of the proxy server's operation. It handles each client
// connection in a separate goroutine, allowing for concurrent handling of multiple clients.
//
// The function performs the following steps:
// 1. Defers closing the Gordafarid connection to ensure cleanup.
// 2. Retrieves the handshake result from the Gordafarid connection.
// 3. Extracts the destination address and port from the handshake result.
// 4. Establishes a connection to the target server.
// 5. Sets up bidirectional data transfer between the client and the target server.
// 6. Handles any errors that occur during the data transfer.
//
// Parameters:
//   - gc: A pointer to a gordafarid.Conn, which represents the client connection.
//
// The function doesn't return any values, but it logs various information and errors:
// - Warns if unable to get the Gordafarid handshake result.
// - Logs debug information about the handshake and connection process.
// - Warns if unable to dial the target server.
// - Logs errors that occur during data transfer, except for io.EOF which is expected.
//
// Error handling:
//   - If an error occurs during the handshake or when dialing the target server,
//     the function logs the error and returns, closing the connection.
//   - Errors during data transfer are logged, but don't cause the function to return immediately.
//
// Concurrency:
// - The function uses goroutines and a WaitGroup to handle bidirectional data transfer concurrently.
// - It creates an error channel to collect errors from the data transfer goroutines.
// Note: This function is designed to be run as a goroutine for each incoming connection.
func (s *Server) handleConnection(gc *gordafarid.Conn) {
	// Close the Gordafarid connection when the function returns
	defer gc.Close()

	// Get the handshake result from the Gordafarid connection
	logger.Debug("Getting the Gordafarid handshake result...")
	handshakeResult, err := gc.GetHandshakeResult()
	if err != nil {
		logger.Error(errors.Join(errUnableToGetGordafaridHandshakeResult, err))
		return
	}

	// Extract target server information from the handshake result
	dstAddr := utils.IPBytesToString(handshakeResult.Atyp, handshakeResult.DstAddr)
	dstPort := binary.BigEndian.Uint16(handshakeResult.DstPort[:])
	targetAddr := net.JoinHostPort(dstAddr, fmt.Sprint(dstPort))

	// Log debug information about the handshake and connection process
	logger.Debug("The Gordafarid handshake result received")

	// Establish a connection to the target server with a timeout
	logger.Debug("Connecting to: ", dstAddr)
	tconn, err := net.DialTimeout("tcp", targetAddr, time.Duration(s.cfg.Timeout.DialTimeout)*time.Second)
	if err != nil {
		// Log a warning if unable to connect to the target server
		logger.Warn(errors.Join(shared_error.ErrServerDialFailed, err))
		return
	}
	// Close the target server connection when the function returns
	defer tconn.Close()

	// Log the target server address, handling domain names separately
	if handshakeResult.Atyp == protocol.AtypDomain {
		logger.Debug(fmt.Sprintf("Connected to: %s(%s)", dstAddr, tconn.RemoteAddr()))
	} else {
		logger.Debug("Connected to: ", tconn.RemoteAddr())
	}

	// Set up bidirectional data transfer
	wg := sync.WaitGroup{}
	wg.Add(2)
	errChan := make(chan error, 2)

	// Log the proxying information
	logger.Debug(fmt.Sprintf("Proxying between %s/%s", gc.RemoteAddr(), tconn.RemoteAddr()))

	// Start a goroutine to copy data from client to remote server
	go utils.DataTransfering(&wg, errChan, tconn, gc)
	// Start a goroutine to copy data from remote server to client
	go utils.DataTransfering(&wg, errChan, gc, tconn)

	// Close the error channel after both data transfer goroutines are finished
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Handle and log errors from the data transfer goroutines
	for err := range errChan {
		// Ignore EOF errors as they are expected when connections close
		if !errors.Is(err, io.EOF) {
			logger.Error(err)
		}
	}
}
