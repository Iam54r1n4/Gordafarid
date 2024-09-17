package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/Iam54r1n4/Gordafarid/core/net/utils"
	"github.com/Iam54r1n4/Gordafarid/internal/config"
	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

// HandshakeResult is used to communicate the result of the handshake
type HandshakeResult struct {
	DstAddr string // Target address
	DstPort int    // Target port
	ATyp    byte   // Address type
	Err     error  // Error, if any
}

// Handshake performs the SOCKS5 handshake process
// This function follows the SOCKS5 protocol as defined in RFC 1928 and RFC 1929
// https://www.ietf.org/rfc/rfc1928.txt
// https://www.ietf.org/rfc/rfc1929.txt
// It handles the initial greeting, method selection, authentication (if required), and the SOCKS5 request

// Client -> Server: Initial Greeting
// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+

// Server -> Client: Method Selection
// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+

// If USERNAME/PASSWORD authentication is selected:
// Client -> Server: Username/Password Authentication
// +----+------+----------+------+----------+
// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
// +----+------+----------+------+----------+
// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
// +----+------+----------+------+----------+

// Server -> Client: Authentication Response
// +----+--------+
// |VER | STATUS |
// +----+--------+
// | 1  |   1    |
// +----+--------+

// Client -> Server: SOCKS5 Request
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+

// Server -> Client: SOCKS5 Reply
// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+

// VER: SOCKS version (0x05 for SOCKS5)
// NMETHODS: Number of authentication methods supported
// METHODS: Authentication methods supported
// CMD: Command (0x01 for CONNECT, 0x02 for BIND, 0x03 for UDP ASSOCIATE)
// RSV: Reserved byte, must be 0x00
// ATYP: Address type (0x01 for IPv4, 0x03 for Domain, 0x04 for IPv6)
// DST.ADDR: Destination address
// DST.PORT: Destination port
// REP: Reply field (0x00 for success, other values for various errors)
// BND.ADDR: Server bound address
// BND.PORT: Server bound port
// ULEN: Username length
// UNAME: Username
// PLEN: Password length
// PASSWD: Password
// STATUS: Authentication status (0x00 for success, 0x01 for failure)
func (s *Socks5) Handshake(cfg *config.ClientConfig) <-chan HandshakeResult {
	hChan := make(chan HandshakeResult)

	go func() {
		defer close(hChan)

		var err error
		// Step 1: Handle initial greeting and method selection
		if err = s.handleInitialGreeting(); err != nil {
			hChan <- HandshakeResult{Err: err}
			return
		}

		// Select preferred authentication method
		bestMethod, err := s.selectPreferredSocks5AuthMethod()
		if err != nil {
			hChan <- HandshakeResult{Err: err}
			return
		}

		// Verify best method
		if err = s.verifyMethods(cfg, bestMethod); err != nil {
			hChan <- HandshakeResult{Err: err}
			return
		}

		// Step 2: Send method selection message
		if err = s.sendTwoBytesResponse(socks5Version, bestMethod); err != nil {
			hChan <- HandshakeResult{Err: err}
			return
		}

		// Step 3: Handle authentication if required
		if bestMethod == userPassAuthMethod {
			if err = s.handleUserPassAuthMethodNegotiation(cfg); err != nil {
				hChan <- HandshakeResult{Err: err}
				return
			}
		}

		// Step 4: Handle SOCKS5 request
		if err = s.handleSocks5Request(); err != nil {
			hChan <- HandshakeResult{Err: err}
			return
		}

		// Step 5: Send success response
		if err = s.sendSocks5SuccessResponse(); err != nil {
			hChan <- HandshakeResult{Err: err}
			return
		}

		// Step 6: Return successful handshake result
		var dstAddr string
		switch s.request.atyp {
		case utils.AtypIPv4, utils.AtypIPv6:
			dstAddr = net.IP(s.request.dstAddr).String()
		case utils.AtypDomain:
			dstAddr = string(s.request.dstAddr)
		}
		dstPort := binary.BigEndian.Uint16(s.request.dstPort[:])

		hChan <- HandshakeResult{DstAddr: dstAddr, DstPort: int(dstPort), ATyp: s.request.atyp}
	}()
	return hChan
}

// handleInitialGreeting processes the initial SOCKS5 greeting from the client
// It reads the client's supported authentication methods and selects one
func (s *Socks5) handleInitialGreeting() error {
	// Read SOCKS version and number of methods
	buf := make([]byte, 2)
	if _, err := utils.ReadWithContext(s.ctx, s.conn, buf); err != nil {
		s.gretting.methods = []byte{noAcceptableMethod}
		return errors.Join(proxy_error.ErrSocks5UnableToReadVersion, err)
	}

	// Verify SOCKS version
	if buf[0] != socks5Version {
		s.gretting.methods = []byte{noAcceptableMethod}
		return errors.Join(proxy_error.ErrSocks5UnsupportedVersion, fmt.Errorf("sent version: %d", buf[0]))
	}
	s.gretting.version = buf[0]

	// Verify number of methods
	nMethods := buf[1]
	if nMethods == 0 {
		s.gretting.methods = []byte{noAcceptableMethod}
		return errors.Join(proxy_error.ErrSocks5InvalidNMethodsValue, fmt.Errorf("sent nmethods: %d", nMethods))
	}
	s.gretting.nMethods = buf[1]

	// Read authentication methods
	methods := make([]byte, nMethods)
	if _, err := utils.ReadWithContext(s.ctx, s.conn, methods); err != nil {
		s.gretting.methods = []byte{noAcceptableMethod}
		return errors.Join(proxy_error.ErrSocks5InvalidNMethodsValue, fmt.Errorf("sent nmethods: %d", nMethods), err)
	}
	s.gretting.methods = methods
	return nil
}

// sendTwoBytesResponse sends a two-byte response to the client
func (s *Socks5) sendTwoBytesResponse(version, method byte) error {
	if _, err := s.conn.Write([]byte{version, method}); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToSendVersionResponse, err)
	}
	return nil
}
